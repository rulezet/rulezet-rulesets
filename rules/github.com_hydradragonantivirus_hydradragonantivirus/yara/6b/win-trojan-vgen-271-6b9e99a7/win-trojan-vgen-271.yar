rule Win_Trojan_VGEN_271
{
strings:
	$a0 = { 213c047228b452cd21fc26c577220e07bf5600a5a58c4cfec744fc5600b80480ababab8cc8488ed8be0800a5a5 }


condition:
	$a0
}