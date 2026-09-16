rule Win_Trojan_Signed_1
{
strings:
	$a0 = { 803e09000074178a160900bb4100bfef038a0732c2 }


condition:
	$a0
}