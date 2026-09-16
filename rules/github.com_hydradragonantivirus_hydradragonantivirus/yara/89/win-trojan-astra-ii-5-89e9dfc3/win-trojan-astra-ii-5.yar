rule Win_Trojan_Astra_II_5
{
strings:
	$a0 = { 0b0003f58bfeb984018bddfcad2e3387cb03abe2f75b07 }


condition:
	$a0
}