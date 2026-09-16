rule Win_Trojan_Bancos_951
{
strings:
	$a0 = { 3c1be58e7149861c790ef035e94ee87323d53e417aee974e80fb71bbb97f11febeaa7833b8ab7f2b6ed8ce257def246739d9ab32fb102c8b19a9d6d83fb57428cd50f7fdb7f8aca7211070f8961a }


condition:
	$a0
}