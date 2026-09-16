rule Win_Trojan_Dowcipas_1
{
strings:
	$a0 = { e800005d81ed3404b430cd218a5e0c8cda3c047213b8f19cbeeb09cd213da767750981f94fda7503e925018e062c00 }


condition:
	$a0
}