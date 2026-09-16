rule Win_Trojan_Parity_3
{
strings:
	$a0 = { b901ba000103d7cd21b801578b8d }


condition:
	$a0
}