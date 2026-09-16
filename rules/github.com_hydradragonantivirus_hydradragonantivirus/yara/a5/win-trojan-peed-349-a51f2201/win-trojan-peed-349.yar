rule Win_Trojan_Peed_349
{
strings:
	$a0 = { 89e554e84e000000ab50525183c8ff4005d58c400029db8b0853ffd18d580159 }


condition:
	$a0
}