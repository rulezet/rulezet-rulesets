rule Win_Spyware_4219_1
{
strings:
	$a0 = { 8b45f4ba1c964000e841a6ffff7514b8e0f94000b9349640008b55f4e82da5ffffeb67 }


condition:
	$a0
}