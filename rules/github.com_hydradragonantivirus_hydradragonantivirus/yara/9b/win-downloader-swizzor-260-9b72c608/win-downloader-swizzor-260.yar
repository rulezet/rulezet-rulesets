rule Win_Downloader_Swizzor_260
{
strings:
	$a0 = { 4859b3a32b436e05f0bcd7d52d5e2227aea20c4585870abff42bf6164a2204103bdcb3d28b57c5063ca25b3003f03caa }


condition:
	$a0
}