rule Win_Trojan_Proxy_111
{
strings:
	$a0 = { 558becb90b0000006a006a004975f9b8240c4300e80e004b2833 }

	$a1 = { 5c7b46434144444331342d }


condition:
	$a0 and $a1
}