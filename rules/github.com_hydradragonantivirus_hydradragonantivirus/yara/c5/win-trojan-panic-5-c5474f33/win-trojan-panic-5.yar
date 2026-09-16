rule Win_Trojan_Panic_5
{
strings:
	$a0 = { 70616e69632e706c }

	$a1 = { 666c6f6f64696e672024686f73743a24706f7274 }


condition:
	$a0 and $a1
}