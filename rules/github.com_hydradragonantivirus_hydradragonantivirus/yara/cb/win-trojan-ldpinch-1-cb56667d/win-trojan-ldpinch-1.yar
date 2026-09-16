rule Win_Trojan_LdPinch_1
{
strings:
	$a0 = { ca64a10a706173c4776f7d72e1d3d6268538034d69637272d23d66747fcf66644f777e06437572bece9c569dfe1e696f }


condition:
	$a0
}