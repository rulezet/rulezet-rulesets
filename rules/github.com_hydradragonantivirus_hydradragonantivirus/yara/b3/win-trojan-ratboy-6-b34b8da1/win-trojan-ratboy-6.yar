rule Win_Trojan_Ratboy_6
{
strings:
	$a0 = { eb28903e8b8641018db64301b9f20031044646e2fa }


condition:
	$a0
}