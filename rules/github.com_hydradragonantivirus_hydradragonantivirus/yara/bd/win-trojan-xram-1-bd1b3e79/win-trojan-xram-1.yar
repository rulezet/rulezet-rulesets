rule Win_Trojan_Xram_1
{
strings:
	$a0 = { cd21b901008d964802b440cd21b8024233c933d2cd218386180204b440b9e8038d960601cd21 }


condition:
	$a0
}