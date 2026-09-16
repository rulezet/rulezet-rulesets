rule Win_Trojan_Trident_1
{
strings:
	$a0 = { 1aba00fdcd21e4210c02e6213402e621b44e8d96560133c9cd217334e9de00faebfd }


condition:
	$a0
}