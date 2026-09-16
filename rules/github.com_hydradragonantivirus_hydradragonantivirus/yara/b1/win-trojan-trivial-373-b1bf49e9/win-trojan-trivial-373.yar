rule Win_Trojan_Trivial_373
{
strings:
	$a0 = { aa0ac075fab456268865fe5fcd217217b43cb102cd210e1f93b440b95800ba0001cd21b43ecd21 }


condition:
	$a0
}