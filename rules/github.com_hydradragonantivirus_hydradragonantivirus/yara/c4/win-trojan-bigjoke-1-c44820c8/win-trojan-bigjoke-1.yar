rule Win_Trojan_BigJoke_1
{
strings:
	$a0 = { 8be883c5030e588ed88ec08d7643bf00 }


condition:
	$a0
}