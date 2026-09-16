rule Win_Trojan_Airwalker_2
{
strings:
	$a0 = { 8d76098bfeb98200adcc7304abe2f9c3352c5c73f7 }


condition:
	$a0
}