rule Win_Trojan_Feliz_2
{
strings:
	$a0 = { b924048bd5cd21e88700e8a700b440b91a008d962004 }


condition:
	$a0
}