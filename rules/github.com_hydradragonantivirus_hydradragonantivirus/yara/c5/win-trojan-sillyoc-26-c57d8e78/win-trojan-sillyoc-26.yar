rule Win_Trojan_SillyOC_26
{
strings:
	$a0 = { 40e90100e9b601e90100e9b200e90100e98aeae90100e9b1f79090e90100e9cd21e90100e9b43e }


condition:
	$a0
}