rule Win_Trojan_ZVE_1
{
strings:
	$a0 = { a0359a9a120292112f8a1b30e40348339a19085cb9fb4b5c0a05619c1c2a5575b1b801474b }


condition:
	$a0
}