rule Win_Trojan_Find_4
{
strings:
	$a0 = { 5e8d74fdb95e01b0b58cd5fa8bdc0e178be683c4235a32f032d052fa4444e2f5 }


condition:
	$a0
}