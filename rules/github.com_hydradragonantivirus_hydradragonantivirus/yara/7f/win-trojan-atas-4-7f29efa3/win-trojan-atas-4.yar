rule Win_Trojan_Atas_4
{
strings:
	$a0 = { 3e0201b0beb97c0cbe130001fe300446e2fb42e900f8b2bf4001bebf07b8be4d1ae1067315739f8304 }


condition:
	$a0
}