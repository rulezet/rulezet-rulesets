rule Win_Trojan_Involuntary_1
{
strings:
	$a0 = { 8cc8908ed88ec033f68bfefc9090ad9033c2ab90e2f7e9 }


condition:
	$a0
}