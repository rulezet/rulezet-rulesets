rule Win_Trojan_Renia_1
{
strings:
	$a0 = { ff1e833e0e02007403e998bbf236807db03f7df38b }


condition:
	$a0
}