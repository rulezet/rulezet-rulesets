rule Win_Trojan_Gen_102
{
strings:
	$a0 = { 8ec33b158e1d8b154a8eda8bf1 }


condition:
	$a0
}