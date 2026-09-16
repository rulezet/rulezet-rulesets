rule Win_Trojan_Transmitter_2
{
strings:
	$a0 = { 521e069ce8000058902d0900ba0000bb1000f7f38ccb03c32d10000e8ed858a35c07322732273ae47404b44ccd }


condition:
	$a0
}