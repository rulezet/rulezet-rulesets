rule Win_Trojan_Hammer_1
{
strings:
	$a0 = { 581e2d040050b4d5cd213d56347503e9b8005f5706 }


condition:
	$a0
}