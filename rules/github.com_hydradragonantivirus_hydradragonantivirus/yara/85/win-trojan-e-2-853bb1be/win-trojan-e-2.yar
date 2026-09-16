rule Win_Trojan_E_2
{
strings:
	$a0 = { b85c0050b90001fcf3a5cb0e1f8ec1ba8000410ee8040022166c01b80102cd13cbb801039cff1e }


condition:
	$a0
}