rule Win_Trojan_Knat_1
{
strings:
	$a0 = { eb14582d54616e6b004d61646520696e }


condition:
	$a0
}