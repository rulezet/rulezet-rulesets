rule Win_Trojan_Letter_H_2
{
strings:
	$a0 = { e800005e81eef601b80035cd218d941502b80025cd2140b8 }


condition:
	$a0
}