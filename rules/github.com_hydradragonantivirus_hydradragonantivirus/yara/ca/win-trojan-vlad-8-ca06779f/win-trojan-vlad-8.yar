rule Win_Trojan_VLAD_8
{
strings:
	$a0 = { 4449b94a012e813500004747e2f7c35d81ed03001e }


condition:
	$a0
}