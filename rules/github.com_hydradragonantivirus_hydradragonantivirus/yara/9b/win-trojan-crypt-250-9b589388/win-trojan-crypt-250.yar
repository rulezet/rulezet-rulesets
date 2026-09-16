rule Win_Trojan_Crypt_250
{
strings:
	$a0 = { 57c7c755afb4df8d3d5fba581affcf0facf7f20fbdfef7 }

	$a1 = { 5e3d2677090d604a45655965 }


condition:
	$a0 and $a1
}