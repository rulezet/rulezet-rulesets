rule Win_Trojan_K_29
{
strings:
	$a0 = { bac102b90300b440cd217207bac903b409cd21833ebf02ff74088b1ebf02b43ecd212e833e03 }


condition:
	$a0
}