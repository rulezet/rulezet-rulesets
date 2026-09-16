rule Win_Trojan_SillyE_7
{
strings:
	$a0 = { 59cd21e83600b440b93202ba0001cd21b801578b36eb028b54188b4c16cd21b43ecd21b801 }


condition:
	$a0
}