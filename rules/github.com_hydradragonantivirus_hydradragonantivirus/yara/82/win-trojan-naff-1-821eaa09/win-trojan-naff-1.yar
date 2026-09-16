rule Win_Trojan_Naff_1
{
strings:
	$a0 = { a62b898c60dc8832bc8c31bd8b3cc860a0883088cabb41bb5a60968832888c318c883cc8609b8830 }


condition:
	$a0
}