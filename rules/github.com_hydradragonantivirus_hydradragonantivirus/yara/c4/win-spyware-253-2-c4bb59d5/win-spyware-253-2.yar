rule Win_Spyware_253_2
{
strings:
	$a0 = { 558bec83c4f0535657b8a49b4000e831b3ffff68f89c40006a006a00e8efb3ffffa3c8ba4000e84db4ffff3db7000000750da1c8ba400050e8abb4ffffeb72 }


condition:
	$a0
}