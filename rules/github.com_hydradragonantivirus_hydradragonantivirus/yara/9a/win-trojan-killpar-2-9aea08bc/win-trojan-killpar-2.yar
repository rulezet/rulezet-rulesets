rule Win_Trojan_Killpar_2
{
strings:
	$a0 = { 2806e80500b44ccd21c3b80102bb2801b90100ba8000cd13c706260355aab80103cd13b001c3 }


condition:
	$a0
}