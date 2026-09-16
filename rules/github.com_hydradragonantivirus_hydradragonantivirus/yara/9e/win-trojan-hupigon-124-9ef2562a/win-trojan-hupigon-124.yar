rule Win_Trojan_Hupigon_124
{
strings:
	$a0 = { 6a00a1a8e248008b00e8ea95f7ff50e8f0b8f7ffa114e24800803800742ca1a8e248008b00e8ce95f7ff506a01a1c4e048008b00e8bf95f7ff8bc8ba00b94800b801000080e8f6bbfcff }


condition:
	$a0
}