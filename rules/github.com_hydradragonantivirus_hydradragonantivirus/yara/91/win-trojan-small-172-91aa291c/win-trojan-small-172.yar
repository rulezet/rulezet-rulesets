rule Win_Trojan_Small_172
{
strings:
	$a0 = { 015760fcbeff0003750166a533c98ec1bf0402b1e626803dbf741cf3a48ed966a1840066a3cc0266a3040066a30c }


condition:
	$a0
}