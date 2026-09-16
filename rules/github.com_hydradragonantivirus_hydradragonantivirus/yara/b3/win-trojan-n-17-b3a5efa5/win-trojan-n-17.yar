rule Win_Trojan_N_17
{
strings:
	$a0 = { ed03001e060e1fe84602b80666cd2181fb5a527453b44abbffffcd2183eb2890b44acd21b448bb2700cd21723b48 }


condition:
	$a0
}