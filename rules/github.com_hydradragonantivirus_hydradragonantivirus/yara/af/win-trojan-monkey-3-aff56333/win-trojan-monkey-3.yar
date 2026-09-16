rule Win_Trojan_Monkey_3
{
strings:
	$a0 = { 14044f8905b106d3e004208ec0c38a34b80103e8e1ff }


condition:
	$a0
}