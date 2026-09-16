rule Win_Trojan_SSR_4
{
strings:
	$a0 = { e800005e5381ee0d01562e8a360101b9c40230b42601fec646e2f75e }


condition:
	$a0
}