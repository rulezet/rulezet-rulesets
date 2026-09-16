rule Win_Trojan_B_78
{
strings:
	$a0 = { 7cb90a0080fa807411b103b0fd3806157c7402b10eb601eb049032f690b80102fbcd13ffe3 }


condition:
	$a0
}