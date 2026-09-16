rule Win_Trojan_Sexquiz_1
{
strings:
	$a0 = { 6168616861686121210d0a008db62000b85e01ffd08db63300b87001ffd08db63b00b87001ff }


condition:
	$a0
}