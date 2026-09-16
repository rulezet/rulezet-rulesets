rule Win_Trojan_PS_35
{
strings:
	$a0 = { fa018916fc015bb91a0051b440ba0000b9f401cd21b8004233c933d2cd2159b440baf801cd21b8 }


condition:
	$a0
}