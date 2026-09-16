rule Win_Trojan_Ratboy_5
{
strings:
	$a0 = { eb28903e8b8651018db65301b9da0031044646e2fa }


condition:
	$a0
}