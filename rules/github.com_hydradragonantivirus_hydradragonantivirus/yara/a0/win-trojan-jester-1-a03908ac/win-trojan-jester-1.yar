rule Win_Trojan_Jester_1
{
strings:
	$a0 = { b801faba4559cd16e800005d81ed0d018db6da01bf0001a5a58d96de01b41acd21fe8ebb018d96bb01b44ecd2172 }


condition:
	$a0
}