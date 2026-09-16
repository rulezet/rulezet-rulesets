rule Win_Spyware_3650_2
{
strings:
	$a0 = { 578d3a81c7da25406f87d75f545268da25406f5a }


condition:
	$a0
}