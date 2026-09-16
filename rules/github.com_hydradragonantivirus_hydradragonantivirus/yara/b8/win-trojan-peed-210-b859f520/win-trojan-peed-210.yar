rule Win_Trojan_Peed_210
{
strings:
	$a0 = { 89c1bb73e41400fc711f5589e5870203550803550cc9c208005589e58b5d0885db7402ffd3 }


condition:
	$a0
}