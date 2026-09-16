rule Win_Trojan_B_44
{
strings:
	$a0 = { 91b80102cd13061e071f81bffe0155aa75e932f6b90200b701b80302cd13b88c02 }


condition:
	$a0
}