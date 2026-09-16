rule Win_Trojan_VGEN_312
{
strings:
	$a0 = { 8cc8908ed8908ec090b800012be890fb9090fc9090b82020be212e03f090bf352e03f89005e2ddcd2f90b8e020 }


condition:
	$a0
}