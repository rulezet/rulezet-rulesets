rule Win_Downloader_Small_1199
{
strings:
	$a0 = { aab831703238343546ac6871741c703a2f50773c2e4ac4bea98c3c657b0d62697a2fa2ce54739c705f63ce6578527b4be9 }


condition:
	$a0
}