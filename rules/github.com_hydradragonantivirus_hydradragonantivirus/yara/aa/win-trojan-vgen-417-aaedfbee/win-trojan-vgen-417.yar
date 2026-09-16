rule Win_Trojan_VGEN_417
{
strings:
	$a0 = { 061eb83412cd213d21437502eb458cd8488ec026832e030022832e020022a102002d10008ec0be00018bfeb90d }


condition:
	$a0
}