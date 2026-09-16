rule Win_Trojan_Small_170
{
strings:
	$a0 = { 5760fcbeff0003750166a533c98ec1bf0402b1db26803dbf741cf3a48ed966a1840066a3c30266a3040066a30c }


condition:
	$a0
}