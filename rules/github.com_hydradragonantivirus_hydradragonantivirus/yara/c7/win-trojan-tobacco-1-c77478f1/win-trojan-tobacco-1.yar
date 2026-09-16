rule Win_Trojan_Tobacco_1
{
strings:
	$a0 = { 8ed8b800012b0684058bd0a18205030684058bc8b4408b1e8005cd218a4600cc894600e84501 }


condition:
	$a0
}