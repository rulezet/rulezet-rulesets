rule Win_Trojan_OneHalf_22
{
strings:
	$a0 = { 2bdbfabc007c8ed38edb832e130404cd12b106d3e08ec006b90b00b80702ba8000cd1372f3b8d60050cb }


condition:
	$a0
}