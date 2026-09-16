rule Win_Trojan_Delf_829
{
strings:
	$a0 = { 6240008d855cdfffffba1d000000e8f9beffff8d45e8ba06000000e8ecbeffffc3e962bcffffebdb5f5e5b8be55dc300ffffffff0300000050574400ffffffff1500000050574450617373776f726420 }


condition:
	$a0
}