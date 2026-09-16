rule Win_Spyware_ye_258
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ffcd09de1ab9ec9ec0ed907a1abff7 }


condition:
	$a0
}