rule Win_Trojan_Rael_2
{
strings:
	$a0 = { a10188f60e1f88ff8b0788ff8b0e050188f633c188ff890788ff4388ff81fb450d88ff740d }


condition:
	$a0
}