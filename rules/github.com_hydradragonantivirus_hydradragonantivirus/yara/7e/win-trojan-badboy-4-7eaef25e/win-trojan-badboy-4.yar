rule Win_Trojan_BadBoy_4
{
strings:
	$a0 = { 0383c30253518b078b4f108bd830 }


condition:
	$a0
}