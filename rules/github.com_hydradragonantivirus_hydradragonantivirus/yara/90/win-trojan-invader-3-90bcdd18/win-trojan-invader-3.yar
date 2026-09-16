rule Win_Trojan_Invader_3
{
strings:
	$a0 = { b106d3e08ed8833e400efe751ab8 }


condition:
	$a0
}