rule Win_Trojan_Havjiva_1
{
strings:
	$a0 = { ec01cd21e81f00b440b105baa601cd215a59b80157 }


condition:
	$a0
}