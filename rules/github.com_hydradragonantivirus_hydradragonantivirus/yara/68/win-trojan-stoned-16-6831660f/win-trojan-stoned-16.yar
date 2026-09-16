rule Win_Trojan_Stoned_16
{
strings:
	$a0 = { c0070000009800ffffffe4008097007c00001e5080fc02721780fc04731233c08ed80ad2750aa03f04a8017503 }


condition:
	$a0
}