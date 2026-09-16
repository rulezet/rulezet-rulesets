rule Win_Trojan_Pakes_984
{
strings:
	$a0 = { 5783ec0c8bfc6a006a0057b86f64666fabb87833322eabb8646c6c00abe8????000083c40c5f83f8027c1066b9504503 }


condition:
	$a0
}