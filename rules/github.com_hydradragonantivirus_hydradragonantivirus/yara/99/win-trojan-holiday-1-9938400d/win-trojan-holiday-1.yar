rule Win_Trojan_Holiday_1
{
strings:
	$a0 = { 3f8b1e8a00cd215b58c350538b1e8a00b440cd215b58c35053b800428b1e8a00cd215b58c3 }


condition:
	$a0
}