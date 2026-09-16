rule Win_Trojan_FatherVirus_1
{
strings:
	$a0 = { b802faba4559cd1356bf000181c67701b90300f3a45eb824efcd213d01fe742bb82135cd21bfc10203fe891d8c }


condition:
	$a0
}