rule Win_Trojan_Kalunu_2
{
strings:
	$a0 = { 41560090cfe8e800b44fe905fde887fce86dfcb933058d960001b440cd21e85ffce873fcc3 }


condition:
	$a0
}