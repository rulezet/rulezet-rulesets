rule Win_Trojan_Perflog_51
{
strings:
	$a0 = { e95f100000000000009090906a006858 }

	$a1 = { 0072696e73742e657865 }


condition:
	$a0 and $a1
}