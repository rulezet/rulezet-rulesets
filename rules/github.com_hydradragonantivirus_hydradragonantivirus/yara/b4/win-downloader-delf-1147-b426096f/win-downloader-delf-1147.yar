rule Win_Downloader_Delf_1147
{
strings:
	$a0 = { 6738f4045e1ed4114750f2dc1a6db7f0f20ec9e1a1baecd204a15eb2d4202eac13c4c62d1e2c3033233a6c6b87e843c091627bc26dfed01c40966c49e1d62f2dcbe1a57fe745ff9afaccfc1e1bf1dc43cd }


condition:
	$a0
}