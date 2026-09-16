rule Win_Trojan_Vgen_136
{
strings:
	$a0 = { 07b40eaccd10e2fb32e4cd16c353bb0000cd215bc39cfa9a74077000c3558beceb23817e04 }


condition:
	$a0
}