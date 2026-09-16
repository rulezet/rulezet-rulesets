rule Win_Spyware_ye_106
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]67b5714682215406a8d5f8e282275f }


condition:
	$a0
}