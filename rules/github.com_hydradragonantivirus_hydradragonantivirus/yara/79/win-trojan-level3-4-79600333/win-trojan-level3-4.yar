rule Win_Trojan_Level3_4
{
strings:
	$a0 = { 10be203cb89eadcd316aefcfda0509ba6447f971e9de9915916c75083368ef }


condition:
	$a0
}