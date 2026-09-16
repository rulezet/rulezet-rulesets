rule Win_Trojan_Xolominer_2
{
strings:
	$a0 = { 4c61756e63682e626174 }

	$a1 = { 666c61736875702e657865 }


condition:
	$a0 and $a1
}