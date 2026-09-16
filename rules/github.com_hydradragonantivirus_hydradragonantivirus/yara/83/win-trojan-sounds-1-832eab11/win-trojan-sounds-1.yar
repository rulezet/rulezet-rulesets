rule Win_Trojan_Sounds_1
{
strings:
	$a0 = { d1009a000053005589e581ec0202e8e6febf14030e57e800febf27030e57e8f8fdbf37030e57e8f0fdbf42030e }


condition:
	$a0
}