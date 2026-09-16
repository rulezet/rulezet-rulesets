rule Win_Trojan_Occido_2
{
strings:
	$a0 = { ed0601e917008dbe170189fee81c018dbe250189feb9f300b203e8f3008db6ef01bf0001b90300f3a48db6ec018d }


condition:
	$a0
}