rule Win_Trojan_TinyGhost_1
{
strings:
	$a0 = { 8785e0feabe3f7931e07c33d004b74052eff2ea401 }


condition:
	$a0
}