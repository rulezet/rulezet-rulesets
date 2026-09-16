rule Win_Trojan_BadTrans_2
{
strings:
	$a0 = { 6563 }

	$a1 = { 6179 }

	$a2 = { 46656213615361274672690054687500??9d5bfe576564005475656f172f }


condition:
	$a0 and $a1 and $a2
}