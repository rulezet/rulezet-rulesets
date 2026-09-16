rule Win_Trojan_I_Love_Dos_2
{
strings:
	$a0 = { 0626890e000026891602008cc88ed8b9ff0d8d9c3701b0382807d0c043e2f9e9b6fd }


condition:
	$a0
}