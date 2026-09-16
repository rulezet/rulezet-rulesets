rule Win_Trojan_R_45
{
strings:
	$a0 = { 40b9a203cd21b8004233c9cd21b440b90400ba9a03cd21b801572e8b0e92032e8b16900380e1e0 }


condition:
	$a0
}