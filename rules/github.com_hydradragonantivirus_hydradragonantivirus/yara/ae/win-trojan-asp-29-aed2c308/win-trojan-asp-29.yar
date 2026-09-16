rule Win_Trojan_ASP_29
{
strings:
	$a0 = { 227878646f632229 }

	$a1 = { 633a5c72756e2e636d64 }

	$a2 = { 64697220633a5c2f732f6f64203e633a5c6c6f672e747874 }


condition:
	$a0 and $a1 and $a2
}