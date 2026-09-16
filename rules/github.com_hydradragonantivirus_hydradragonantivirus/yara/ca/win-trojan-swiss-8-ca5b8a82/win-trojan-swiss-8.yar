rule Win_Trojan_Swiss_8
{
strings:
	$a0 = { 742ba12c00501fba0800b8003dcd21721b8bd82ec68444 }


condition:
	$a0
}