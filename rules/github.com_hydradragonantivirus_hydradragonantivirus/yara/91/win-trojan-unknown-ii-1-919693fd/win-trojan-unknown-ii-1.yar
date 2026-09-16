rule Win_Trojan_Unknown_II_1
{
strings:
	$a0 = { 9869eec1d113461ef5a65e96c30d9948987958aebce41b8c232b34fe8386224b9c4942b57bf4764b }


condition:
	$a0
}