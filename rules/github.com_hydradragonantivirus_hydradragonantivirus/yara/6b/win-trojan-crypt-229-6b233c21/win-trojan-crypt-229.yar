rule Win_Trojan_Crypt_229
{
strings:
	$a0 = { 2bc0740ed11df3e3cb3df7edda17c6e9cf16515183c404893c240f }


condition:
	$a0
}