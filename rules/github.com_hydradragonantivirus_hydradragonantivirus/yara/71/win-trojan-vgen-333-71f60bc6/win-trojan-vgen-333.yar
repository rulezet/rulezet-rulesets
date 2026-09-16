rule Win_Trojan_VGEN_333
{
strings:
	$a0 = { 02b1defa8becbc312558d3c8f7d050eb01234c4c4a75f29d06c11233d1acad8cb7b0acada2bf05d03fdccd6ddcc9 }


condition:
	$a0
}