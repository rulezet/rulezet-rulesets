rule Win_Trojan_Hybrid_1
{
strings:
	$a0 = { ee75028bfeb9de01ac34deaa4975f9 }


condition:
	$a0
}