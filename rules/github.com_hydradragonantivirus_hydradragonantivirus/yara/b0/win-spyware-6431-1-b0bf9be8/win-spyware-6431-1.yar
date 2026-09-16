rule Win_Spyware_6431_1
{
strings:
	$a0 = { 575f565683c40481ef772b091581c777 }


condition:
	$a0
}