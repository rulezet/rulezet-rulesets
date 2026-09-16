rule Win_Trojan_Aids_2
{
strings:
	$a0 = { 89863601b4408b5e028d963501b90300cd21b4428b5e02b900008b96330183c204b000cd21 }


condition:
	$a0
}