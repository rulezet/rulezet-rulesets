rule Win_Trojan_CPP_4
{
strings:
	$a0 = { 015760beff00037501fc66a529c98ec1bf0402b90a0126803dbf7414f3a48ed966a1840066a30a03ba5002b82125 }


condition:
	$a0
}