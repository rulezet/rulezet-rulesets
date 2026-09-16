rule Win_Trojan_Transmitter_3
{
strings:
	$a0 = { 51521e069ce8000058902d0900ba0000bb1000f7f38ccb03c32d10000e8ed858a3a006e8c300bf0001a1a0068ec0 }


condition:
	$a0
}