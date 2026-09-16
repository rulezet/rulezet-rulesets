rule Win_Trojan_Vienna_33
{
strings:
	$a0 = { eb04ff066a00c40666008cc2b90a0031 }


condition:
	$a0
}