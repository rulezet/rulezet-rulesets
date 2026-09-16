rule Win_Trojan_Monster_37
{
strings:
	$a0 = { 02bede2cfc300446e2fb25cdcd934e23ce0b89c13326cd0b89c1cd255ecc464981cf444994cf0acbcdcc00ed }


condition:
	$a0
}