rule Win_Trojan_Hupigon_544
{
strings:
	$a0 = { 558bec807d0801750b66b88200e8eefeffffeb0966b89001e8e3feffff5dc20400 }


condition:
	$a0
}