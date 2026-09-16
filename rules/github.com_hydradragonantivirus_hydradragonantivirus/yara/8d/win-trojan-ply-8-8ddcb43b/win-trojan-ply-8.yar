rule Win_Trojan_Ply_8
{
strings:
	$a0 = { 018cc8908ed8908ec090b800012be890fb9090fc9090b82020be212e03f090bf352e03f89005e2ddcd2f90b44190 }


condition:
	$a0
}