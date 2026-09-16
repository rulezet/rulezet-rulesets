rule Win_Trojan_Golwant_1
{
strings:
	$a0 = { 55bd????b9c401814600????83edfee2f6 }


condition:
	$a0
}