rule Win_Trojan_Scapny_1
{
strings:
	$a0 = { bbffffcd218bd83d0800753790b9e1022e8a80da022e280446fec0e2f8 }


condition:
	$a0
}