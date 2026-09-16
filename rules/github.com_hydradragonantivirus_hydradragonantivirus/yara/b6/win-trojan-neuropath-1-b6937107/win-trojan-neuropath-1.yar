rule Win_Trojan_NeuroPath_1
{
strings:
	$a0 = { 8ed8be8400bf7900a5a5c744fc60008c44fe071febc19c2eff1e7900c33d8657741880fc4c74 }


condition:
	$a0
}