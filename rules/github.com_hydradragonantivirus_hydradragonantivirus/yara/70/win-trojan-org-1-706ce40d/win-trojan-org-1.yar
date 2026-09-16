rule Win_Trojan_Org_1
{
strings:
	$a0 = { 03cd130e1fb92000bebe05bfbe01f3a52ec606af0100b90100ba8000bb0000b80103cd136a00 }


condition:
	$a0
}