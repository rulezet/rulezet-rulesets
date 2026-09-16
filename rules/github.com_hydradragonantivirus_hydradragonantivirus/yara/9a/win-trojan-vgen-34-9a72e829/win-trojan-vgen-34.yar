rule Win_Trojan_VGEN_34
{
strings:
	$a0 = { 6907b9d100871c86fbfaeb0990d1c3e80800eb2190e80200ebf3501e33c08ed8eb01ea87060400eb019a87060c0087 }


condition:
	$a0
}