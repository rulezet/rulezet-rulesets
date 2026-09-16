rule Win_Trojan_Hupigon_1422
{
strings:
	$a0 = { 8d55c4a1d0e84000e8b99fffff8b45c48d4dc8ba90c14000e801deffff8b45c8e8a57fffffa3cce84000e80ffbffff33c05a5959648910682fc140008d45c4ba0b000000e8317bffffc3 }


condition:
	$a0
}