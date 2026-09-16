rule Win_Trojan_HappyBox_1
{
strings:
	$a0 = { b8007c8bf08be033c08ed0fb8ed8a113042d0300a31304c1e0068ec033ffb900011e56fcf3a581c7000206578bdf2e }


condition:
	$a0
}