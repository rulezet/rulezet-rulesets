rule Win_Trojan_Ren_1
{
strings:
	$a0 = { 83c607301cd1cb02dfac03d0e2f55e80740680895402 }


condition:
	$a0
}