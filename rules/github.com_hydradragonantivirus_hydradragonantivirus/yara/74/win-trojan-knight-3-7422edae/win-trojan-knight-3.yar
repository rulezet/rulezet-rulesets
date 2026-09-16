rule Win_Trojan_Knight_3
{
strings:
	$a0 = { 89054681fe11017503be070181c7020081ff7005 }


condition:
	$a0
}