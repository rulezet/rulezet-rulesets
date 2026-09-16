rule Win_Trojan_Koths_2
{
strings:
	$a0 = { 06fbfb50fbfb51fbfb8cc8fbfb8ed8fbfb8ec0fbfbbe????fbfb8bfefbfbb99209fbfbfcfbfbacfbfb34??fbfbaafbfbe2f4 }


condition:
	$a0
}