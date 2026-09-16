rule Win_Trojan_Gonads_1
{
strings:
	$a0 = { 40b9f5068d940301cd21b800429933c9cd218b8438082d }


condition:
	$a0
}