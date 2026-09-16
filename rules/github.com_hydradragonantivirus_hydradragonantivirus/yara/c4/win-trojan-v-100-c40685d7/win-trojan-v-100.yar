rule Win_Trojan_V_100
{
strings:
	$a0 = { 2e89360001e80300e943ffe800005e515750b9290381ee3803e801006e5f2e8a052e300446e2fa }


condition:
	$a0
}