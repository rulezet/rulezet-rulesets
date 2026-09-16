rule Win_Trojan_Packed_134
{
strings:
	$a0 = { 6892??????????3c }

	$a1 = { 558bec83ec0c535657eb01c8833d40????00007408eb01 }


condition:
	$a0 and $a1
}