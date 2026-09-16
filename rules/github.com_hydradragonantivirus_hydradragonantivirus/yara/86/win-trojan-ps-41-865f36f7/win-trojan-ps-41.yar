rule Win_Trojan_PS_41
{
strings:
	$a0 = { 10008036080028b440b94002ba4002cd2133c9b8004299cd2159b440ba8504cd21b801575a }


condition:
	$a0
}