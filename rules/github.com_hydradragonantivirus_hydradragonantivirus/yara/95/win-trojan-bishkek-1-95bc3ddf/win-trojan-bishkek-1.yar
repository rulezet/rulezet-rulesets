rule Win_Trojan_Bishkek_1
{
strings:
	$a0 = { ba8000b90100bb0201c7471a0000cd13eb1ab409ba14028bf2b92b0051fe0c46e2fbcd2159 }


condition:
	$a0
}