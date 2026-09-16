rule Win_Trojan_Light_4
{
strings:
	$a0 = { 8edffa8ed7be007c8bde8be6fbff0e1304cd12b90602d3e08ec0b825000650f3a4cbfabea0 }


condition:
	$a0
}