rule Win_Trojan_Necrophilia_1
{
strings:
	$a0 = { 8b164e00890e1c7c89161e7cfcbe007c31ffb90002f3a4b801028b0e187c8b161a7cbb0002cd1306 }


condition:
	$a0
}