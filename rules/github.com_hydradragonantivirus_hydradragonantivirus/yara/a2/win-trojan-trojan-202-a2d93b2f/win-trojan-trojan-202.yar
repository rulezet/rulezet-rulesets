rule Win_Trojan_Trojan_202
{
strings:
	$a0 = { 16035bb4408d960001b9a501ccb8004233c933d2cc8d961203b440b91a00ccfe861103b80157 }


condition:
	$a0
}