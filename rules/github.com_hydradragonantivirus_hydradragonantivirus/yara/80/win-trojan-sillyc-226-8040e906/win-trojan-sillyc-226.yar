rule Win_Trojan_SillyC_226
{
strings:
	$a0 = { 21722493b6feb43fcd21b00252e820005aa30501b440cd2132c0e81300b601b440cd21b43ecd21 }


condition:
	$a0
}