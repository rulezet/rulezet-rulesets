rule Win_Trojan_Spooky_7
{
strings:
	$a0 = { 1e0e0e071fe800005d81ed09018db65e028dbe3c02b90400f3a5b42fcd2106531e07b41a8d968902cd21b44e8d9666 }


condition:
	$a0
}