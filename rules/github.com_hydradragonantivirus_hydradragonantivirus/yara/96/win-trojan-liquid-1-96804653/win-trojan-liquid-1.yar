rule Win_Trojan_Liquid_1
{
strings:
	$a0 = { 04eb04eb06ebfaeb00ebf85351508d9e1d01b9c2012e8b86f0042e31074343e2f958595bc35351 }


condition:
	$a0
}