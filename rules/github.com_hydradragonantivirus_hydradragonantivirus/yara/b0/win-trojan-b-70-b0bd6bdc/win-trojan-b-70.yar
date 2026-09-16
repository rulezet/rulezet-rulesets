rule Win_Trojan_B_70
{
strings:
	$a0 = { 7c33d2f7361a7c8ae8b106d2e48acc8a36047c0ace58b0018af28a16fd7dcd135ac3 }


condition:
	$a0
}