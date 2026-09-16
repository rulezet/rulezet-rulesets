rule Win_Spyware_58983_1
{
strings:
	$a0 = { 31c0e801000000c331ff89e581ec880000008d9578ffffff6a }

	$a1 = { 66486e7e31460860464d6e41685448 }


condition:
	$a0 and $a1
}