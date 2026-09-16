rule Win_Trojan_Jak_5
{
strings:
	$a0 = { 81ed0600b41a8d96d500cd21bf00018db64f0057a4a4a4e83400c3cd202a2e636f6d005b4a614b2e50617261736974 }


condition:
	$a0
}