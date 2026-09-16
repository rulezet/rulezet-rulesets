rule Win_Trojan_Virogen_6
{
strings:
	$a0 = { 41086d200b74b053e0aee046ab3e2620e34ee7a6ed2023154ee7a67121377ce34ee7a671216e6e4e }


condition:
	$a0
}