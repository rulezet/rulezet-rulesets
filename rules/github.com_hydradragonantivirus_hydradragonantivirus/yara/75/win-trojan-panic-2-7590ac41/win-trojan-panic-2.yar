rule Win_Trojan_Panic_2
{
strings:
	$a0 = { b801438bd583c21e8b4e3ccd21b44fcd217203e977fffab002b93200551e33db33d28edacd26 }


condition:
	$a0
}