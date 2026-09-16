rule Win_Trojan_AAEH_4
{
strings:
	$a0 = { 7a616969646b77 }

	$a1 = { f256bfeabf029bd67091c13d46af90cde18ed02792a6ddef9b7fb773988d83c96703c81ed7602cf5e0a0d444e5089184 }


condition:
	$a0 and $a1
}