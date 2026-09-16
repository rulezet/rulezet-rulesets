rule Win_Trojan_SillyOC_10
{
strings:
	$a0 = { 01cd21813e6701b000741bb80042b90000ba0000cd21b440ba0001b98100cd21b43ecd21eb0e }


condition:
	$a0
}