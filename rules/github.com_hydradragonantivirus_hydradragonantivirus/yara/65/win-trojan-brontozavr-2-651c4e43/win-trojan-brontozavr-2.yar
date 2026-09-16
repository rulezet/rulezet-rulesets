rule Win_Trojan_Brontozavr_2
{
strings:
	$a0 = { 582d030050b4aacd213d22227503eb70908cd8488ed8812e030060018cd8408ed8a102002d6001a302008ec0 }


condition:
	$a0
}