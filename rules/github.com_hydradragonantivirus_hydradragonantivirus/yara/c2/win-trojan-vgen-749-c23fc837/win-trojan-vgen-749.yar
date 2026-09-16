rule Win_Trojan_VGEN_749
{
strings:
	$a0 = { 6301cd21b8cf08c1e8048ccb03d88ec3b9320051b43c33c9ba5b01cd2193b92900ba930153bb000150e5402503 }


condition:
	$a0
}