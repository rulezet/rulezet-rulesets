rule Win_Trojan_Fisu_1
{
strings:
	$a0 = { 018bf847b0012e8a05343d2e8805b001b8be7da80129f8473c014875e9b0015f58c3 }


condition:
	$a0
}