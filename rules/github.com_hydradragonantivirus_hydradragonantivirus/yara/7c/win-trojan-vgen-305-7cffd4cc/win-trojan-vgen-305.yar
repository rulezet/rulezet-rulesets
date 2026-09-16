rule Win_Trojan_VGEN_305
{
strings:
	$a0 = { 018b5e0081c30301bd00018a57fc8856008a57fd8856018a57fe88560253eb062a2e434f4d00b44e5a5283c222b9 }


condition:
	$a0
}