rule Win_Trojan_Firepass_2
{
strings:
	$a0 = { 4669726550617373776f7264 }

	$a1 = { 6e65745c66697265666f782e6578655c7368656c6c5c6f70656e5c }


condition:
	$a0 and $a1
}