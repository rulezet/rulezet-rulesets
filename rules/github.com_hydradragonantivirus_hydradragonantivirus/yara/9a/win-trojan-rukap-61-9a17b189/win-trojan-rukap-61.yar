rule Win_Trojan_Rukap_61
{
strings:
	$a0 = { 72fe27f72df3f8a601f36f589aef757832a897c03d4a87c65ff3f1463a6029ad3dce198ee6cf0ad8cb527326d458ce59f02324d8dca5d62791860563f2fe2c48c54cd3a9c35ab7ed }


condition:
	$a0
}