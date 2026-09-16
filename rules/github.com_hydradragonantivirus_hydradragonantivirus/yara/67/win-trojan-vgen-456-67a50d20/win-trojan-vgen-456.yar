rule Win_Trojan_VGEN_456
{
strings:
	$a0 = { 8bfac605631e52b90700b44ecd217235b42fcd215f8b0557061f8a572480ca203ad075178947 }


condition:
	$a0
}