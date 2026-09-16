rule Win_Trojan_Spooky_13
{
strings:
	$a0 = { ffe90500b8004ccd21e2f6e800005d81ed13018db6240189f7b9a002e8a002e440247f3c02751eb80300cd108db6 }


condition:
	$a0
}