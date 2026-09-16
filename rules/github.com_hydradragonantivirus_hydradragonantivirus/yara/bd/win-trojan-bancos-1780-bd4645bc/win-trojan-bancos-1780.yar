rule Win_Trojan_Bancos_1780
{
strings:
	$a0 = { 9d479bcd1113f5657994688ff220fdd1722c78f6b1106cf10831a1a0fb2c4b3cdda6f2be4bbb441fb295396353b33eedbc84d82a03077e46cfaad9ad374ae1db0e0861eafb2e }


condition:
	$a0
}