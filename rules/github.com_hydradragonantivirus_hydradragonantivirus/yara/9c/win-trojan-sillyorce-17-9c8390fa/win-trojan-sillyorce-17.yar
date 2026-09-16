rule Win_Trojan_SillyORCE_17
{
strings:
	$a0 = { 518ec1bfb00426390d7517be0001b142fcf3a48ed966b8d6040000668706840066abcb80fc4b75161eb8023dcd }


condition:
	$a0
}