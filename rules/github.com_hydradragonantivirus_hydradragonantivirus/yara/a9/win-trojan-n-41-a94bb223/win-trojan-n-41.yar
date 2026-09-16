rule Win_Trojan_N_41
{
strings:
	$a0 = { fa8ed3bc007c8ec4fbb99950ba0000fcbf03002ae4cd13b80502cd13730b4f75f2be487ce80700cd19ea9700007c }


condition:
	$a0
}