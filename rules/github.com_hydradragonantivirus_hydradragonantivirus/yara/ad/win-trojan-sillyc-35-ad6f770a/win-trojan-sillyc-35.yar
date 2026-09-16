rule Win_Trojan_SillyC_35
{
strings:
	$a0 = { 01b987008d960301cd21b8004233c999cd21b44180f401b903008d968901cd21b43ecd21 }


condition:
	$a0
}