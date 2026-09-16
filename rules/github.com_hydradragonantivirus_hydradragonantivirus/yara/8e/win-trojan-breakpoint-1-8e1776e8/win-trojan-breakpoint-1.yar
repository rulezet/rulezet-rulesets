rule Win_Trojan_Breakpoint_1
{
strings:
	$a0 = { 7e4132f6b280cd1372eb803e217e337428b405b179cd16b80103b90200cd13b405b179cd16fc }


condition:
	$a0
}