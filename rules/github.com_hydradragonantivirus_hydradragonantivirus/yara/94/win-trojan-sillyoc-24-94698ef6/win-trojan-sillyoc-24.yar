rule Win_Trojan_SillyOC_24
{
strings:
	$a0 = { 01cd218bfa813d84e97426803d4d7421b8004233c933d2cd21b440b1cf9090ba0001cd21b801 }


condition:
	$a0
}