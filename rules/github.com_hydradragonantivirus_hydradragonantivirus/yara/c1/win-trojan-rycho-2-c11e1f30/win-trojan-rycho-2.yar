rule Win_Trojan_Rycho_2
{
strings:
	$a0 = { 06ba0000e8ceffb8fefecd213dcaba7403e885018cc98ed9a18d008b1e8f00e81200071fbaff00e8abff8cd903c105 }


condition:
	$a0
}