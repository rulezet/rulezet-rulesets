rule Win_Trojan_Pakes_991
{
strings:
	$a0 = { 57b86f64666fabb87833322eabb8646c6c }


condition:
	$a0
}