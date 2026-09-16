rule Win_Trojan_Lucifer_2
{
strings:
	$a0 = { aad590cd21903d032a90745c908bc4 }


condition:
	$a0
}