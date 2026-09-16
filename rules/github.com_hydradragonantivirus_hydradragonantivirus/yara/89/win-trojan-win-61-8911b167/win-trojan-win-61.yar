rule Win_Trojan_Win_61
{
strings:
	$a0 = { b3c9b9a6c7e5c0edb2a1b6becec4bcfe21[0-3]cce1cabe[0-4]5c5c2e5c504859534943414c445249564530 }


condition:
	$a0
}