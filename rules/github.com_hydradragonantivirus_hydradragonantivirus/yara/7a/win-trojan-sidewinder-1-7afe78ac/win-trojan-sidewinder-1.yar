rule Win_Trojan_Sidewinder_1
{
strings:
	$a0 = { 1eb8ffffcd213d042174748cc88ed88ec0be7e02bf7d02b98800e87900be5205bf5105b92600e86d00b82135cd21 }


condition:
	$a0
}