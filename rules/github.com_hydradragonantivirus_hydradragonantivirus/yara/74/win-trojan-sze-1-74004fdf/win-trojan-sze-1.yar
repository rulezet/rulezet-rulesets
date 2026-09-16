rule Win_Trojan_Sze_1
{
strings:
	$a0 = { 3dba9e00cd218bd8b002e8e8ffa303008bca8bd083ea }


condition:
	$a0
}