rule Win_Trojan_Leprosy_5
{
strings:
	$a0 = { ba2e01b44ecd213d12007414e83b008b1e4b01535bb99200ba0001b440cd21c3ba3401b43bcd2175d4eb5f2a2e }


condition:
	$a0
}