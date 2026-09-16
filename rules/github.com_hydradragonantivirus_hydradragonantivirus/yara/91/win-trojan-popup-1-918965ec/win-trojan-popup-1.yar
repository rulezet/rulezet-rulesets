rule Win_Trojan_Popup_1
{
strings:
	$a0 = { 897dfce8700e00008bc883c404894de43bcfc645fc01740e68f8714000e8460700008bd8eb02 }


condition:
	$a0
}