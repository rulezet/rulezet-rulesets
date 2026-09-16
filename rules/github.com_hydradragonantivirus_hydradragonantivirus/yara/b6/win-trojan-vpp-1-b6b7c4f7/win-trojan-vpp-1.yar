rule Win_Trojan_Vpp_1
{
strings:
	$a0 = { b04daa33c0aac3505351528d967a04b43c33c9cd21720c938bd5b9c004e8afffe8adfd5a59 }


condition:
	$a0
}