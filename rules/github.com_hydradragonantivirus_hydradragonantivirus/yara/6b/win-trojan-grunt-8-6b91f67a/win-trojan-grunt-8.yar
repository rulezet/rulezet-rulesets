rule Win_Trojan_Grunt_8
{
strings:
	$a0 = { b9d100408d9e3401903e8b96d602f7d0 }


condition:
	$a0
}