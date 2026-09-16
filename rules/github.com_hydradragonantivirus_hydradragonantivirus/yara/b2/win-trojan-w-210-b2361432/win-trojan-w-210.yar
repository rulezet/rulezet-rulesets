rule Win_Trojan_W_210
{
strings:
	$a0 = { 140000b924634000b8a0600d01290135209a1b009083e9044b75f2e9baacffff00000000 }


condition:
	$a0
}