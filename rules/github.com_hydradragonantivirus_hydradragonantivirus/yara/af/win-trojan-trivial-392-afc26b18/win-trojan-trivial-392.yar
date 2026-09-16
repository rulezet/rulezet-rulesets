rule Win_Trojan_Trivial_392
{
strings:
	$a0 = { b8c5902bc94db4d980f4974681ea71c4cd21f9b80f014fba4244f5350d3c81eaa44390cd21f8ba07e48bd881 }


condition:
	$a0
}