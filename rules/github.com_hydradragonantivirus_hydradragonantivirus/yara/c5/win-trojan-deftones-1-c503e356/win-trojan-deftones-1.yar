rule Win_Trojan_Deftones_1
{
strings:
	$a0 = { 4637304e33532e434f4d01200345584503434f4d9a000008019a0d008b005589e5b804069acd }


condition:
	$a0
}