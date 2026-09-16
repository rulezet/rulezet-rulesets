rule Win_Dropper_Agent_33942
{
strings:
	$a0 = { 6a166a0a8b0d60b64100b201a1f00e4100e8deb6ffff8945fc8d45f0b9348441008b157cb84100e8fcc3feff8b55f08b45fce8f1b4ffff33c05a5959648910 }


condition:
	$a0
}