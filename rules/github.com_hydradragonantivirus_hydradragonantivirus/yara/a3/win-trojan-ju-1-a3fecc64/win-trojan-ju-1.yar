rule Win_Trojan_Ju_1
{
strings:
	$a0 = { 83ee03b466cd21722a83fcfe751181c61f00bf000157a5a5c3fbea909090908cc00510002e014421053412fa8ed0bc }


condition:
	$a0
}