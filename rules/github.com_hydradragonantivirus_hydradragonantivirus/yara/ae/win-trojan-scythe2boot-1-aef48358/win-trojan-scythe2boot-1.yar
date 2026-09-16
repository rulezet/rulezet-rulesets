rule Win_Trojan_Scythe2Boot_1
{
strings:
	$a0 = { be7004bf080db9a2013bfc7204b44ccd21fdf3a5fc8bf7bf0001adad8be8b210e99a0b }


condition:
	$a0
}