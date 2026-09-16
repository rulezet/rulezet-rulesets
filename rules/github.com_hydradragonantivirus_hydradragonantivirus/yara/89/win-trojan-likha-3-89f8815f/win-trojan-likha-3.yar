rule Win_Trojan_Likha_3
{
strings:
	$a0 = { e0052174ba9ee3c6b8153bc3aa09ca7c11050d01d3c61b018a15aa9c5fb25dc0689cdd9dda1bfabb }


condition:
	$a0
}