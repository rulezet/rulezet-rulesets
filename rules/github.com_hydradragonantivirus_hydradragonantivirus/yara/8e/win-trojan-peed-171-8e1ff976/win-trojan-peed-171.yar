rule Win_Trojan_Peed_171
{
strings:
	$a0 = { 89c1bb73e41400fc71415589e58b5d0885db7402ffd3c9c204005589e5870203 }


condition:
	$a0
}