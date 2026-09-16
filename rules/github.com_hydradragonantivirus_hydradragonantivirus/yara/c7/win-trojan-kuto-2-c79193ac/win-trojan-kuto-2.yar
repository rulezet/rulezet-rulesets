rule Win_Trojan_Kuto_2
{
strings:
	$a0 = { 6a00e8610000008bd803583c8b9b80000000891dd92040 }


condition:
	$a0
}