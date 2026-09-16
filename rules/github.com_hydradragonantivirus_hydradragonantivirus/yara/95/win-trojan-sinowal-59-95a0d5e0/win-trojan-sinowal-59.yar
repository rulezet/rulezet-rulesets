rule Win_Trojan_Sinowal_59
{
strings:
	$a0 = { e80000025050ff1558204000cc558bec81 }

	$a1 = { 5c69626d2a2e646c6c }

	$a2 = { 5c245f323334313233342e544d50 }


condition:
	$a0 and $a1 and $a2
}