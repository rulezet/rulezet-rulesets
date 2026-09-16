rule Win_Trojan__0030_0001_006_1
{
strings:
	$a0 = { c98bd1b802422e8b1e390f9cfa2eff1ee80dc38becb80057e8ebffbb630f890f895702e8c802 }


condition:
	$a0
}