rule Win_Trojan_Mini386_2
{
strings:
	$a0 = { 5152cd212d030097b4408bd5b97b0090cd21b800425a59cd21fdc604e9897c01fc87d6b90400 }


condition:
	$a0
}