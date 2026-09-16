rule Win_Trojan_LazyToday_1
{
strings:
	$a0 = { f3a45e1f06b84d0050cbb843fdbb1200cd213d1256741a }


condition:
	$a0
}