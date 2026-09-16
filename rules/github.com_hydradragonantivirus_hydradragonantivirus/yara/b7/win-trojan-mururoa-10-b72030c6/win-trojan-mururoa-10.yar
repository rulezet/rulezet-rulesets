rule Win_Trojan_Mururoa_10
{
strings:
	$a0 = { 6c646f7261646f2e43616c6970706fe205eb1d5eeb1c2e3014eb12b92500eb072e8a94b207ebf481c6b307ebe9 }


condition:
	$a0
}