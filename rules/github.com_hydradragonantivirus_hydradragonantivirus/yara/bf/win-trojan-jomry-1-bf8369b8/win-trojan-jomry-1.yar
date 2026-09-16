rule Win_Trojan_Jomry_1
{
strings:
	$a0 = { e9019a0d004e015589e5b800059acd02e90181ec0005e803f68dbe00ff1657bf42001e57b8e3ff509a00000c01 }


condition:
	$a0
}