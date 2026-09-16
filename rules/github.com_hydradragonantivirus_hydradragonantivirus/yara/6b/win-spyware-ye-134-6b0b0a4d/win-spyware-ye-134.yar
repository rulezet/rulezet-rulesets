rule Win_Spyware_ye_134
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]83498d5a9ec5f09ac4e99406aecbfb }


condition:
	$a0
}