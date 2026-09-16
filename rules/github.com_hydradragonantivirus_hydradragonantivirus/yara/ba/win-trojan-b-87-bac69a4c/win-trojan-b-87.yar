rule Win_Trojan_B_87
{
strings:
	$a0 = { 060002eb3cbe3e00b97a018b048884000246e2f7b80103bb0002b90100b6009cff1e1e01 }


condition:
	$a0
}