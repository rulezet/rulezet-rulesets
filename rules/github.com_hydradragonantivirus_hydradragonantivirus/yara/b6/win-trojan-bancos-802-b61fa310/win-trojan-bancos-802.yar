rule Win_Trojan_Bancos_802
{
strings:
	$a0 = { 856d934e4ba462fda9e436e42c86dba8b633d56abe7cb112a451d6a7a157e16d77f1485a2c81665bde4cc27fec9ad02c299f717fa9bad6ab5f1849f5542b00c7a0ce48955385 }


condition:
	$a0
}