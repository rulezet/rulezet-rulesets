rule Win_Trojan_KGBKeylog_2
{
strings:
	$a0 = { 4d706b2e646c6c }

	$a1 = { 47004500540020002f0069006d002f00730065006e00640049004d }


condition:
	$a0 and $a1
}