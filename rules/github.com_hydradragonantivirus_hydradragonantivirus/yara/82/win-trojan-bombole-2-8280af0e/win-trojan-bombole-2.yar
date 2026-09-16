rule Win_Trojan_Bombole_2
{
strings:
	$a0 = { cd211f619de9b8fe5b424f4d424f4c452076312e355d20627920474f424c45454e20 }


condition:
	$a0
}