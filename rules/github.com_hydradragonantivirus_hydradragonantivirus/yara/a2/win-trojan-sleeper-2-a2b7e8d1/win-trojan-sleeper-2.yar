rule Win_Trojan_Sleeper_2
{
strings:
	$a0 = { 01b90f048bf7ac32c4aae2fac3905e81ee030156e8e2 }


condition:
	$a0
}