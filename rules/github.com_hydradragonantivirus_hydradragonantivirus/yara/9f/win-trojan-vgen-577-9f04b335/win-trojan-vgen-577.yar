rule Win_Trojan_VGEN_577
{
strings:
	$a0 = { e601cd21b8003c33c9ba16020e1fcd2193891ee001b42ccd21a1e201d3c803c203c10106e2018bea83e51fbb00 }


condition:
	$a0
}