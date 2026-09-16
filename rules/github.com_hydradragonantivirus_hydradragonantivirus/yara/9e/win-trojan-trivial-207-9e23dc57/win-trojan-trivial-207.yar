rule Win_Trojan_Trivial_207
{
strings:
	$a0 = { ba2201b44ecd21ba9e00b8013dcd2193b44180ec01b92400b126ba0001cd21cd21c32a2e436f }


condition:
	$a0
}