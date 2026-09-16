rule Win_Trojan_Waledac_44
{
strings:
	$a0 = { 558bec83ec708b0d9acb45008d35b7034f0003ce81e9572d000074f6 }


condition:
	$a0
}