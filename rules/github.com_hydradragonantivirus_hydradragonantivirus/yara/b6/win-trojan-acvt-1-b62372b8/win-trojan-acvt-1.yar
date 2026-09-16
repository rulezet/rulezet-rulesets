rule Win_Trojan_ACVT_1
{
strings:
	$a0 = { 320ab80000ba0000b503b180e891ffc31e53a058012c41b9010080fc257504cd25eb02cd265b5b }


condition:
	$a0
}