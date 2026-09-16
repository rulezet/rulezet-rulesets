rule Win_Trojan_BOO_7
{
strings:
	$a0 = { 02bb00015326813f5224740bcd135b721806b8020150cbbb000fb001b109cd135b720606b805 }


condition:
	$a0
}