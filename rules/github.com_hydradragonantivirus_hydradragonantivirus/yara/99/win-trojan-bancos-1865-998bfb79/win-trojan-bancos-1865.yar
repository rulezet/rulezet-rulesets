rule Win_Trojan_Bancos_1865
{
strings:
	$a0 = { b1b6113a294c806c3aa657dd2da551d5b50a6ec99d8c32be644d6094417c23249b200d2e08a0a4e8733e9bfff2fcedb56c55b2a80008d86a20ccba80f405e7f7605bf774d17d }


condition:
	$a0
}