rule Win_Trojan_Taiwan_10
{
strings:
	$a0 = { e702ba0001cd21b442b002b90000ba }


condition:
	$a0
}