rule Win_Trojan_Preacher_2
{
strings:
	$a0 = { 21ba0001b9dc0190b440cd21badc02b4402e8b0e0f01cd21b801578b0e96008b169800cd21b43e }


condition:
	$a0
}