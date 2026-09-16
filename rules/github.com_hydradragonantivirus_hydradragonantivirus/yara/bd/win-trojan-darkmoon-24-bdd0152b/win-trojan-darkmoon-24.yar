rule Win_Trojan_Darkmoon_24
{
strings:
	$a0 = { 8b55d85268a4274000ff15341040008bd08d4dd4ffd7 }


condition:
	$a0
}