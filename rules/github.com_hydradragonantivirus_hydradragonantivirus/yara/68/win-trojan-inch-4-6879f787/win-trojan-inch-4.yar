rule Win_Trojan_Inch_4
{
strings:
	$a0 = { 774ab2f6a082fe4ecff77ca1f7741db743b73ad63172b2f6f7cacff782f87c6a7af7c43ec4254ff7 }


condition:
	$a0
}