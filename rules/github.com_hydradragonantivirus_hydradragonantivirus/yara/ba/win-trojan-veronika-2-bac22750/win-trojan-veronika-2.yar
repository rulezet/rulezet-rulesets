rule Win_Trojan_Veronika_2
{
strings:
	$a0 = { 83ee0b0616fab8bbfbcd21fafc179c5bd0df2ed194fc05 }


condition:
	$a0
}