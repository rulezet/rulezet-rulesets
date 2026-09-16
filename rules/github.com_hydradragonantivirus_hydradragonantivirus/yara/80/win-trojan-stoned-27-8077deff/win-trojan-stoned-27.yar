rule Win_Trojan_Stoned_27
{
strings:
	$a0 = { 50cb31c08ec0cd130e1fbb007cb801028b1608008b0e06000653cd1380fa807403e88e00cb }


condition:
	$a0
}