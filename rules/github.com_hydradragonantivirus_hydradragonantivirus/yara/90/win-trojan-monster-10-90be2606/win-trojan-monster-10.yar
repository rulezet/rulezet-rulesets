rule Win_Trojan_Monster_10
{
strings:
	$a0 = { b9e001bede2cfc300446e2fb26d891cde7e3e7cde7e38e8280cd0aa5db2400e6cde3da25cdcd934e23d70b89ee33 }


condition:
	$a0
}