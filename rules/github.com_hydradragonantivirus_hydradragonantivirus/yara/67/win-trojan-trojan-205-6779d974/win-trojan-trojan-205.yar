rule Win_Trojan_Trojan_205
{
strings:
	$a0 = { e2feb80325ba5c01cd21891eab088c06ad08ba5c01b425cd }


condition:
	$a0
}