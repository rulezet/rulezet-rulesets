rule Win_Trojan_Small_3962
{
strings:
	$a0 = { 8d3dff77d20781efff65890789fe8d9f7c04fe7f81eb0000fe7f6a006aff6a006833030000ff15f816490005f9df23bf0304240107c10f10 }


condition:
	$a0
}