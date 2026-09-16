rule Win_Trojan_Gen_87
{
strings:
	$a0 = { 342e892603012e8c1605012ea307018d }


condition:
	$a0
}