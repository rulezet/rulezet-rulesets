rule Win_Trojan_VGEN_574
{
strings:
	$a0 = { e800005d81ed07016a07e8130cba53566a0be80b0c7429ba4e456a0be8010c741fb80030be0010 }


condition:
	$a0
}