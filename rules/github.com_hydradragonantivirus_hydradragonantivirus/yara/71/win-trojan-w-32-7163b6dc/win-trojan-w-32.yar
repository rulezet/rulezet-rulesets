rule Win_Trojan_W_32
{
strings:
	$a0 = { 06eb0490eb0f908cc88ed82ec70603009090eb2690b88616cd2f0bc07406909090eb4d90b80a000e5bcd31501f80 }


condition:
	$a0
}