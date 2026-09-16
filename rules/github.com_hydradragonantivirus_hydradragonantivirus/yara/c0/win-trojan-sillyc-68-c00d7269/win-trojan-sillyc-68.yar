rule Win_Trojan_SillyC_68
{
strings:
	$a0 = { e837002bc13e8986be01b4408d961701b9a700cd2133c0e82000b4408d96bd01cd218b1686f959b8 }


condition:
	$a0
}