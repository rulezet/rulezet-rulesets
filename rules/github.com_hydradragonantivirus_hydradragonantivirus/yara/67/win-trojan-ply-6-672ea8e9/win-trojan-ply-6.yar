rule Win_Trojan_Ply_6
{
strings:
	$a0 = { b9ffffba76efcd2190b820602d2020b90200ba010103d590cd2190b8004233c99033d290cd }


condition:
	$a0
}