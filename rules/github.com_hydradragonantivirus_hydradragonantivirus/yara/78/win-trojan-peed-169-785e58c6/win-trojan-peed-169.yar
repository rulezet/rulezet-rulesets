rule Win_Trojan_Peed_169
{
strings:
	$a0 = { e8a3000000f7db29dff7db01de89c3eb1b83c40883c4fcbf00??4081bbb7e2faff01c789 }


condition:
	$a0
}