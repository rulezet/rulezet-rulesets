rule Win_Trojan_Agent_32697
{
strings:
	$a0 = { 31058db2c8ec8113bdc723079fd274007351247f008b4a4cf0b3bbf96e0064a7ecd60501c12077c6002258a1285d960b }


condition:
	$a0
}