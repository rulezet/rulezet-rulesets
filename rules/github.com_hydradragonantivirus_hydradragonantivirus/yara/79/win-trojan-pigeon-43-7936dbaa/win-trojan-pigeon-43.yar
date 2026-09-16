rule Win_Trojan_Pigeon_43
{
strings:
	$a0 = { 558bec6aff68a0b7400068009f400064a100000000506489250000000083ec68 }

	$a1 = { 7265706f72742e68746d6c }


condition:
	$a0 and $a1
}