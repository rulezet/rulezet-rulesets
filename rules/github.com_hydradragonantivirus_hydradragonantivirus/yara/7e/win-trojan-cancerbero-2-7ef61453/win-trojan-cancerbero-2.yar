rule Win_Trojan_Cancerbero_2
{
strings:
	$a0 = { 40b901008d96ac02cd21b90200be9a008dbe7302f3a483ae730203b902008d967302b440cd21b9 }


condition:
	$a0
}