rule Win_Trojan_Antimon_2
{
strings:
	$a0 = { 0602722ee891008d167205e89700e82300e8 }


condition:
	$a0
}