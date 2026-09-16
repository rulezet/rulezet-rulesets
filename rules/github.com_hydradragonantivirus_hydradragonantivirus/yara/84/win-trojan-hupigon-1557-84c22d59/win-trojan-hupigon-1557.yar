rule Win_Trojan_Hupigon_1557
{
strings:
	$a0 = { a1e89b4a00803800741da1749a4a008b00e8fc9ff6ff8bc8ba08af4900b801000080e837dcfbff }


condition:
	$a0
}