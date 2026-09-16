rule Win_Trojan_DARK_1
{
strings:
	$a0 = { 33d2b002cd21b440ba050103d68b9c54028b8c7d02cd21c3cd202e813e000133f674f58bc6be }


condition:
	$a0
}