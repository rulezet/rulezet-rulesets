rule Win_Trojan_SomeKit_5
{
strings:
	$a0 = { 929287ca87ca87ca87ca87ca87ca87ca87ca87cae81600eb26e811008d960301b96301b440cd21e80300c3 }


condition:
	$a0
}