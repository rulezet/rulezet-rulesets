rule Win_Trojan_Warning_1
{
strings:
	$a0 = { b413cd2f0652cd2fbb0003b80102ba8001b90100e8f00026813e53030b037434b8010350b600 }


condition:
	$a0
}