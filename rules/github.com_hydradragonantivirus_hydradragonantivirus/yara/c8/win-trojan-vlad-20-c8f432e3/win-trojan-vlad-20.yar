rule Win_Trojan_VLAD_20
{
strings:
	$a0 = { 40b98f0299e83700b80042998bcae82e00b440b918008bd6e82400b801578b0ebe02ba2200e817 }


condition:
	$a0
}