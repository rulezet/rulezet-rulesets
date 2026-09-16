rule Win_Trojan_VGEN_706
{
strings:
	$a0 = { cd21891e9f058c06a105e83400b80102bb9f03b90100ba8000e87900721e817f10cd12741733c08ed8a16c040e }


condition:
	$a0
}