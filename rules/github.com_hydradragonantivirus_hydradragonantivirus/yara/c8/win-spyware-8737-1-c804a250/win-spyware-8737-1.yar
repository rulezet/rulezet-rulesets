rule Win_Spyware_8737_1
{
strings:
	$a0 = { 90558bec9090909083c4f0e945ffffff }


condition:
	$a0
}