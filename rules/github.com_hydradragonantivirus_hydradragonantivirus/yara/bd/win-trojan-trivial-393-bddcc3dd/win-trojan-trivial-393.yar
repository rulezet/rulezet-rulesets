rule Win_Trojan_Trivial_393
{
strings:
	$a0 = { ba300ab41281eaf6084780c43c47cd21f8ba4eefb82517fc05dd2581f2d0efcd21ba316781ea316693 }


condition:
	$a0
}