rule Win_Trojan_Karas_2
{
strings:
	$a0 = { 408d960801b94d0090cd21b93902908db655018dbe9604f3a432e4cd1a8ae180f90074f580f9ff }


condition:
	$a0
}