rule Win_Trojan_CPP_5
{
strings:
	$a0 = { 5760beff00037501fc66a533c98ec1bf0402b90a0126803dbf7414f3a48ed966a1840066a30a03b82125ba5002 }


condition:
	$a0
}