rule Win_Trojan_Ratboy_7
{
strings:
	$a0 = { e80300eb28903e8b8651018db65301b9290131044646e2fa }


condition:
	$a0
}