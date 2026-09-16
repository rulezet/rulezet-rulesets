rule Win_Trojan_Fault_1
{
strings:
	$a0 = { cd217305e8fd02741d8cc82e010644002e01064c00fa2e8e1644002e8b264600fb2eff2e4a008cd80510008bd8 }


condition:
	$a0
}