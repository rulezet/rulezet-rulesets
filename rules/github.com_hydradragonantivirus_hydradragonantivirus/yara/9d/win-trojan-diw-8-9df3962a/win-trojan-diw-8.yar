rule Win_Trojan_DIW_8
{
strings:
	$a0 = { e92609474b808c8a1de9190080000000021f16575ae8bc0152e89401b42fe8c1018bfa2e895d0c81c2e80183c2 }


condition:
	$a0
}