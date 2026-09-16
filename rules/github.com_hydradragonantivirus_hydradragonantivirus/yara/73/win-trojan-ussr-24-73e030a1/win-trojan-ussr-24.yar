rule Win_Trojan_USSR_24
{
strings:
	$a0 = { 01b9b802b440cd2159880eb5031f33c933d2b80042cd21 }


condition:
	$a0
}