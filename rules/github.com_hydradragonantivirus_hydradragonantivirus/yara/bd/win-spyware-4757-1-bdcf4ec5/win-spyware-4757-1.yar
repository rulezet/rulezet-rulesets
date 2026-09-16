rule Win_Spyware_4757_1
{
strings:
	$a0 = { 578934240f00c683c4048b7424fc }


condition:
	$a0
}