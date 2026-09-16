rule Win_Trojan_RedCross_1
{
strings:
	$a0 = { 023dcd21898417048b9c1704b903008d }


condition:
	$a0
}