rule Win_Trojan_Manzon_6
{
strings:
	$a0 = { c1e810a3cf078b1e3107b8004233c999cd21b440b91800bac107cd21c3668bd833c066c1e00c }


condition:
	$a0
}