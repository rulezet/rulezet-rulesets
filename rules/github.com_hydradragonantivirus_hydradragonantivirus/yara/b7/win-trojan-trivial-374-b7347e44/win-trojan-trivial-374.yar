rule Win_Trojan_Trivial_374
{
strings:
	$a0 = { c075fa26c645fe56b4565fcd217217b43cb102cd210e1f93b440b95900ba0001cd21b43ecd21 }


condition:
	$a0
}