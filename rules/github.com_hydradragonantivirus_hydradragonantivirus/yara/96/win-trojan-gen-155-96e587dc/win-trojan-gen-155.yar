rule Win_Trojan_Gen_155
{
strings:
	$a0 = { 61005589e581ec00048dbe00fe16578dbe00ff1657b80100509a8e0961009a5a013e00bf3e001e57b80200509a }


condition:
	$a0
}