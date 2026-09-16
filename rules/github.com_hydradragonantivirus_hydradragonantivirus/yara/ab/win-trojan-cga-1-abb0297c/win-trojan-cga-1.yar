rule Win_Trojan_CGA_1
{
strings:
	$a0 = { 9bea03d95ca852acec51aceb7417f6ddec9bea03c8885154e853fae862fee4e9d87facecab0a1189 }


condition:
	$a0
}