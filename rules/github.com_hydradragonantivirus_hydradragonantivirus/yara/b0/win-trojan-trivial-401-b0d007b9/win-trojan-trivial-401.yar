rule Win_Trojan_Trivial_401
{
strings:
	$a0 = { 9e00cd21b740b95201ba00015053585bcd21b8524febdecd202a2e434f4d00207365636f6e64 }


condition:
	$a0
}