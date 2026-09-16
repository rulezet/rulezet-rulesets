rule Win_Trojan_VGEN_584
{
strings:
	$a0 = { cd2000bb1600ba8f012e8107000043434a75f6e800005d81ed19001e06b83baecd2181fb28cd743a8cc0488ed8812e03008000 }


condition:
	$a0
}