rule Win_Trojan_Mirror_7
{
strings:
	$a0 = { 5a59b80157cd21b43ecd21b82135cd21 }


condition:
	$a0
}