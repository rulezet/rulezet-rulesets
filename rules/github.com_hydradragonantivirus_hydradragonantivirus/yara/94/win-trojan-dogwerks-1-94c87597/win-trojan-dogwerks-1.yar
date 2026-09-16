rule Win_Trojan_Dogwerks_1
{
strings:
	$a0 = { 3b005589e5b800049a7c023b0081ec0004bf9e000e57b83f0050bf82001e579a00003300b00050bfda001e57b8 }


condition:
	$a0
}