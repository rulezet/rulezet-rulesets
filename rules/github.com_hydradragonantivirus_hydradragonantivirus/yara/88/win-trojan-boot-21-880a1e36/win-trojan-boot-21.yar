rule Win_Trojan_Boot_21
{
strings:
	$a0 = { ea007c00005053521e069cb8bcbacd213c9874??0e1ffab82135cd21891e????8c06????b82125 }


condition:
	$a0
}