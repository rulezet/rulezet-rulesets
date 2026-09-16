rule Win_Trojan_VGEN_382
{
strings:
	$a0 = { 8b2d81ed03002e8c9e49022e8c864b0268bbbb58cd2181fb9419752f2e8e9e49022e8e864b02fa8cd82e038622 }


condition:
	$a0
}