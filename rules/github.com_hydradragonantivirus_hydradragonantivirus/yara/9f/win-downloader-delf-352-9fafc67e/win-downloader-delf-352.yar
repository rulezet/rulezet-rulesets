rule Win_Downloader_Delf_352
{
strings:
	$a0 = { b27d7173b27e6eb157ae49c2ff696d676d702e6a70670f5cd4d6d6d6c127d10187c05455023f32a13bdac0138b1d073bec8e39ee07010e01402127ffffcde5d0224426cbccc8 }


condition:
	$a0
}