rule Win_Spyware_ye_199
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c40ace1bdf86315b05aad5c7ef94cc }


condition:
	$a0
}