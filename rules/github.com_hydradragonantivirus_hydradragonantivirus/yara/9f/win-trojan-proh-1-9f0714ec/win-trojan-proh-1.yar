rule Win_Trojan_Proh_1
{
strings:
	$a0 = { 1e060e1f8c060c06b8350186e0cd218c060206891e0006b82501baa70586e0cd21e86905 }


condition:
	$a0
}