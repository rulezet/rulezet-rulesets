rule Win_Trojan_Rogue_2
{
strings:
	$a0 = { 4559b300b802facd13b82435cd212e880e2c012e891e0b012e8c060d011eba2f010e1fb82425cd }


condition:
	$a0
}