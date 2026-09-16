rule Win_Trojan_Kranty_1
{
strings:
	$a0 = { cd217265b0e9a2331033c933d2b80042cd217255b440b90100ba3310cd2183061a1007b440 }


condition:
	$a0
}