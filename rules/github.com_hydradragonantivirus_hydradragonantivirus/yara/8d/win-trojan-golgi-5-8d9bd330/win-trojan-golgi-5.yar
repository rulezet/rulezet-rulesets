rule Win_Trojan_Golgi_5
{
strings:
	$a0 = { 42e82f00721fb440b92200bae001e8220033c933d2b80242e81800b440b9e00133d2e80e00b4 }


condition:
	$a0
}