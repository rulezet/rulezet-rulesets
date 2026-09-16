rule Win_Trojan_Peru_1
{
strings:
	$a0 = { 33dbeb089033dbb403b90100b001cd13c3161ffaff364c00268f06b600ff364e00268f06b800 }


condition:
	$a0
}