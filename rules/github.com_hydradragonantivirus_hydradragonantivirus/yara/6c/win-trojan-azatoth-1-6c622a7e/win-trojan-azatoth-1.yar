rule Win_Trojan_Azatoth_1
{
strings:
	$a0 = { 33c999cd21b4408bd6b91c00cd21b802429933c9cd211e07be8403bf0500e440ba030023c2 }


condition:
	$a0
}