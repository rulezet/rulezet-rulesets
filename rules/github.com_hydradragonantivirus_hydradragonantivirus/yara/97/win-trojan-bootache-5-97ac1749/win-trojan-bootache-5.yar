rule Win_Trojan_Bootache_5
{
strings:
	$a0 = { bb1e00b9e55782ed50b0122e2807fec043e0f8 }


condition:
	$a0
}