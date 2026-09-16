rule Win_Trojan_Agent_34526
{
strings:
	$a0 = { b823ad0c77ba7099cc762bc281f2e0095ce68910c3 }


condition:
	$a0
}