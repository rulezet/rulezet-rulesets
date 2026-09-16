rule Win_Trojan_Small_4254
{
strings:
	$a0 = { 60e9[0-220]78633244 }


condition:
	$a0
}