rule Win_Trojan_Tosha_3
{
strings:
	$a0 = { 73ce3d450176c950b4408bd5b9f20c90cd21b8004233c933d2cd218bf581c6e10cc604e958 }


condition:
	$a0
}