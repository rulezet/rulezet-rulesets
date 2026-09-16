rule Win_Trojan_GenViroverwriting_1
{
strings:
	$a0 = { 2e8b0e2201ba0001cd2173072e8b1e2c01ffe3b80157 }


condition:
	$a0
}