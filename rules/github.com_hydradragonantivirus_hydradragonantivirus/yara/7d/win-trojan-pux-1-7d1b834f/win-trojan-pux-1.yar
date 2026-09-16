rule Win_Trojan_Pux_1
{
strings:
	$a0 = { f6e8dbffb440b9f70433d2e81900ba18002a1609058bcabaf7042bd1b440e8060033f6e8bdffc3 }


condition:
	$a0
}