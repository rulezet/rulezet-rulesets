rule Win_Trojan_Vnu_2
{
strings:
	$a0 = { e800005d81ed14015e5e81ee00018dba3001b9fb019080353847e2fae99a007051415918484854 }


condition:
	$a0
}