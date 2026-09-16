rule Win_Trojan_Bolek_2
{
strings:
	$a0 = { fe24103c107522ff06380d8dbef2fe1657b80e00f726380d8bf881c7ae051e57b80d00509a }


condition:
	$a0
}