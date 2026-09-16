rule Win_Trojan_Erase_boot_1
{
strings:
	$a0 = { b004b403ba0000b90100cd13b8004ccd21b40eb043cd10ebfe }


condition:
	$a0
}