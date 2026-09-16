rule Win_Trojan_Gorb_1
{
strings:
	$a0 = { 061e9cb800008ec026ff3640008f063b0b26ff3642008f063d0bb899009cff1e3b0b9d1f0761fb }


condition:
	$a0
}