rule Win_Trojan_VGEN_649
{
strings:
	$a0 = { da1a0163111433af84a7fd8f88ae7c6311be000156b9fb03c70447ecc64402a88134ae304646e2f831f631c9c300 }


condition:
	$a0
}