rule Win_Trojan_Yury_1
{
strings:
	$a0 = { ab81be1702f0f07502eba10e1fb440b93002908d56fb90cd2133c933d2b80042cd21b440b90300 }


condition:
	$a0
}