rule Win_Trojan_Zork_1
{
strings:
	$a0 = { 1f005589e531c09acd021f00e82dfee83bfee867fee8c3fee89effe80aff5d31c09a16011f00000000000000ba }


condition:
	$a0
}