rule Win_Trojan_Tankar_1
{
strings:
	$a0 = { 42cd21b43fbaf20159cd21803ef401ea7421c6060001e9b43ffec450ba0301b9eb00cd21b8 }


condition:
	$a0
}