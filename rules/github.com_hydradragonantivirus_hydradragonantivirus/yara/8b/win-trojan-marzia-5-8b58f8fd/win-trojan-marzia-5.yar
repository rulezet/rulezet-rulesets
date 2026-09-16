rule Win_Trojan_Marzia_5
{
strings:
	$a0 = { 18b440badc02e85d005a59b80042e8550033d2b440b900048306130001cd21803e230000 }


condition:
	$a0
}