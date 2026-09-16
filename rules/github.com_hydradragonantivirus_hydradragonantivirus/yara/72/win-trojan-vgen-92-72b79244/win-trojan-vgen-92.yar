rule Win_Trojan_Vgen_92
{
strings:
	$a0 = { 0ee800005e83ee0456505351521e06b404cd1a80fe127510e4610c03e661b0b6e643b0e7e642e642fc33c08ed8a11304 }


condition:
	$a0
}