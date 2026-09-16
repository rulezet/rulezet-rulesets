rule Win_Trojan_Futhark_1
{
strings:
	$a0 = { 74bb80fc4e74b980fc4f74b42e803e9501007403e9 }


condition:
	$a0
}