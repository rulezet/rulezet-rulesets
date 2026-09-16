rule Win_Trojan_C_89
{
strings:
	$a0 = { 8b87e14e06894fd1560cf4068cc33b5f08b9b6cd251bc939d9eb10229ed0e2d48b5e0c5e6deb5b }


condition:
	$a0
}