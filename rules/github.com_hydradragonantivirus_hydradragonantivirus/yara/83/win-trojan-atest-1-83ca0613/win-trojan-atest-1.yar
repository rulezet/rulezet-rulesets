rule Win_Trojan_Atest_1
{
strings:
	$a0 = { cd213da18e7444b92c01832e0200138cdb4b8ec326 }


condition:
	$a0
}