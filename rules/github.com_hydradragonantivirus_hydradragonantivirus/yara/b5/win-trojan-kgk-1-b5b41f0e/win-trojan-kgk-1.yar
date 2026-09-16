rule Win_Trojan_KGK_1
{
strings:
	$a0 = { 9b9971c3c3fefd01764f61c21d19a05c5febab664735192beb03989896898e8831cdce26bcbc8f5de9 }


condition:
	$a0
}