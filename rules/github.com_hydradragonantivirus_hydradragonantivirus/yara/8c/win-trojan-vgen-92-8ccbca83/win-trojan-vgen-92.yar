rule Win_Trojan_VGEN_92
{
strings:
	$a0 = { 0181c603018b44fda300018a44ffa20201b8ffffcd213d33337505be0001ffe61e2bc08ed8bb84008bc605e901 }


condition:
	$a0
}