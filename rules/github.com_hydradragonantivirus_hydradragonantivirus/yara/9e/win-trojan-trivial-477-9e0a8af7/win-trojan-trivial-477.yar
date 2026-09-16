rule Win_Trojan_Trivial_477
{
strings:
	$a0 = { 3945b9000090b4684780f4264d81ea6c38cd21ba054ff5b85bf94e2d59bcf581ea674efccd21ba0a0cb96500f8 }


condition:
	$a0
}