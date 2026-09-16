rule Win_Trojan_Kalah_3
{
strings:
	$a0 = { b811008ed8baa601b82125cd21ea4801 }


condition:
	$a0
}