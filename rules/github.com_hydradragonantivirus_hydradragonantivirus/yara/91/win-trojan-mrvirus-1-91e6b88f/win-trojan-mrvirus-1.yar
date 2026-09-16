rule Win_Trojan_Mrvirus_1
{
strings:
	$a0 = { 01bb3e022bd803f346b41a8d5412cd218bde8d77438d }


condition:
	$a0
}