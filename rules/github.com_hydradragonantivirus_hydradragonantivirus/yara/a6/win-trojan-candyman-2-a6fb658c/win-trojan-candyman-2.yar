rule Win_Trojan_Candyman_2
{
strings:
	$a0 = { 01030055ed00000200ffff00000000aa000000070000007008 }


condition:
	$a0
}