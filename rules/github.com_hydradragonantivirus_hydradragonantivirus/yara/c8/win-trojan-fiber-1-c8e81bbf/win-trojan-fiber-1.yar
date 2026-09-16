rule Win_Trojan_Fiber_1
{
strings:
	$a0 = { 8076656ab26545fbb66430e24875edd2b544a74b826a6a2e2ee38fe11c94e98462570ef51f69831a6a6cd5696ad26932d16b6aa74bd26b32d1eb6aa74bde22 }


condition:
	$a0
}