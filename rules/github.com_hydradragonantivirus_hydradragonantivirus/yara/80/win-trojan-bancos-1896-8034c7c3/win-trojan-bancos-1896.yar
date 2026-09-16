rule Win_Trojan_Bancos_1896
{
strings:
	$a0 = { 59a1e5159c29431afee2d3f073f2dc58723d74291b0e930b54acaf29f2c0ad40ec77a476a76775efb54698cdcf14ba47c873f894aca1b51675f3c02accb1a84986850554cb72 }


condition:
	$a0
}