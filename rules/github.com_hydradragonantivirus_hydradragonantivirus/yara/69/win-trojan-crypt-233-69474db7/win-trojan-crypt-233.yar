rule Win_Trojan_Crypt_233
{
strings:
	$a0 = { 03c60dc03f4e35662bc0740a7368030e6948070078625233c12b }

	$a1 = { 6d68616f676f }


condition:
	$a0 and $a1
}