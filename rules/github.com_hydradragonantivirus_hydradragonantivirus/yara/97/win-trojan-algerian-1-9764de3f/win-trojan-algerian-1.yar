rule Win_Trojan_Algerian_1
{
strings:
	$a0 = { b95405908d3e24012e8b3602012e313d2e313547e2f7 }


condition:
	$a0
}