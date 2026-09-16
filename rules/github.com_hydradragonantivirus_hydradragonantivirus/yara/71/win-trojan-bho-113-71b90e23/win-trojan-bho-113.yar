rule Win_Trojan_BHO_113
{
strings:
	$a0 = { 558bec538b5d08568b750c85f6578b7d107509 }

	$a1 = { 434c5349445c }

	$a2 = { 6f70656e[0-4]25735c4b4225692e657865 }


condition:
	$a0 and $a1 and $a2
}