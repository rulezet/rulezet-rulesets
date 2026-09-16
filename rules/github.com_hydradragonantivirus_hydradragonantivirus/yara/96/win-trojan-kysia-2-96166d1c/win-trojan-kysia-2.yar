rule Win_Trojan_Kysia_2
{
strings:
	$a0 = { ba8000b902008ec0bb0000b80602cd13a1????50b8????50cb }


condition:
	$a0
}