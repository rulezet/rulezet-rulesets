rule Win_Trojan_Hacker_3
{
strings:
	$a0 = { 06ffff8cd8488ed8812e03008000 }


condition:
	$a0
}