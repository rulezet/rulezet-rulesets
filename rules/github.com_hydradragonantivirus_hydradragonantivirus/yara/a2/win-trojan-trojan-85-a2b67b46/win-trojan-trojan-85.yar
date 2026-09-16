rule Win_Trojan_Trojan_85
{
strings:
	$a0 = { 0800b800429c2eff1eeb00ba8b00b90200b4409c2eff1eeb0033c92e8b168b0081c20902b80042 }


condition:
	$a0
}