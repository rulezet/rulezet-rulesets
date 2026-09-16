rule Win_Trojan_Sui_1
{
strings:
	$a0 = { ae005589e5b42acd2188165c00803e5c00177729bf03050e57bf5e001e57b8ff00509a9f06ae00bf5e001e57e8 }


condition:
	$a0
}