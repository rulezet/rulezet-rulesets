rule Win_Trojan_Borg_3
{
strings:
	$a0 = { 0901f4b080e621b85346bb0100b90200f3cd2fb9eb09b805feebfc80c43bebf4b800cabb4254cd2f3c007401c3 }


condition:
	$a0
}