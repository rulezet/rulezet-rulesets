rule Win_Trojan_Ceoxme_1
{
strings:
	$a0 = { e2fab90500b440cd21b92f058b16030181c20001b440cd21b801578b0e96008b169800cd21 }


condition:
	$a0
}