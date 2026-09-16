rule Win_Trojan_Banker_4627
{
strings:
	$a0 = { 9c60e8000000005d83ed078d8522fdffff8038010f8442020000c600018bd52b95b6fcffff89 }


condition:
	$a0
}