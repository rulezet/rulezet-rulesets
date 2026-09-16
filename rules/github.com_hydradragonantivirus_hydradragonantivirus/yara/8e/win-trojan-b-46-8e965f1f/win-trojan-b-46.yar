rule Win_Trojan_B_46
{
strings:
	$a0 = { 1f390575aa8747d6a31a03b9c602874fd4890e1803eb2a9186e986f2cd13c3be187c3b1473 }


condition:
	$a0
}