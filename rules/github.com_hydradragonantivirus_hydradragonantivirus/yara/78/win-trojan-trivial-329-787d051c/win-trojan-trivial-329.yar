rule Win_Trojan_Trivial_329
{
strings:
	$a0 = { 90ba3701cd2180c63680ee367225b490b43d9040ba5b00ba9e00cd21b740e9000093ba0001b1dfb13d }


condition:
	$a0
}