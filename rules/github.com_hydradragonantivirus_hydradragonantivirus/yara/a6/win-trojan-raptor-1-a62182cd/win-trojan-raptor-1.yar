rule Win_Trojan_Raptor_1
{
strings:
	$a0 = { 8b1e3f06b90807ba0001cd21583c5975152ea151062e8b164f068b0e45068ed8b443b001cd21 }


condition:
	$a0
}