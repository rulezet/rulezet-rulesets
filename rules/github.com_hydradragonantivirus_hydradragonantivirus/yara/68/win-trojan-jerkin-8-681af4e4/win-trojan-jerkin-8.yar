rule Win_Trojan_Jerkin_8
{
strings:
	$a0 = { e800005d81ed0300eb }

	$a1 = { b43cb900008d96????cd21721e938d86????8d96????e81500b4408d96????b9b101cd21e8 }


condition:
	$a0 and $a1
}