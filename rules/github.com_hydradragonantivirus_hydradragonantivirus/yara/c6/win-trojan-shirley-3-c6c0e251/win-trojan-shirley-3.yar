rule Win_Trojan_Shirley_3
{
strings:
	$a0 = { 4bcd213d636675662ea10e0e8cdb01d80510008ed031 }


condition:
	$a0
}