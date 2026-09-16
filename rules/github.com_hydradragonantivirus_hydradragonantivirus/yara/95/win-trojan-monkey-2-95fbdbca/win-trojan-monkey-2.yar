rule Win_Trojan_Monkey_2
{
strings:
	$a0 = { 1304b106d3e004208ec0c3568bfbbe200003fefcb9dc }


condition:
	$a0
}