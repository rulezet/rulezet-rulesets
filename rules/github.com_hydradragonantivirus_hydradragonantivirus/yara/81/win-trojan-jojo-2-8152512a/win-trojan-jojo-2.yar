rule Win_Trojan_Jojo_2
{
strings:
	$a0 = { 5f005589e581ec0002bf86001e578dbe00fe16578dbe00ff165731c0509ab8095f009a66013c009a7b075f00bf }


condition:
	$a0
}