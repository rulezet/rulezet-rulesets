rule Win_Trojan_SillyC_47
{
strings:
	$a0 = { 8cc80506008ed8bea301bf0001fcb90400f3a4fe0e3901b41abaab01cd21ba9e01b120b43ecd21b44fcd21c6063901 }


condition:
	$a0
}