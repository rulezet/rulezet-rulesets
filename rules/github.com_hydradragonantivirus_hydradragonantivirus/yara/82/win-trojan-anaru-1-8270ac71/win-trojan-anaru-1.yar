rule Win_Trojan_Anaru_1
{
strings:
	$a0 = { 65632e6261740d008db62100b82601ffd08db62a00b82601ffd08db63300b82601ffd08db63b00 }


condition:
	$a0
}