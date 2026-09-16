rule Win_Trojan_Agent_35527
{
strings:
	$a0 = { 558bec83c4f86033fbe98700000081ff6c0c }

	$a1 = { 514a5f574761603625 }


condition:
	$a0 and $a1
}