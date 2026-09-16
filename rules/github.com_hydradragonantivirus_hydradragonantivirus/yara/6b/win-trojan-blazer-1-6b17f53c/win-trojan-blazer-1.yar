rule Win_Trojan_Blazer_1
{
strings:
	$a0 = { cfeb0390fdd38aa64901ac32c4eb0390fbd4aae2f5e9ae }


condition:
	$a0
}