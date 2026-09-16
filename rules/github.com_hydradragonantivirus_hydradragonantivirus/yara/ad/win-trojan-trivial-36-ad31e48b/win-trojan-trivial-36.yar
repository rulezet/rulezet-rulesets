rule Win_Trojan_Trivial_36
{
strings:
	$a0 = { 75fab456268865fe5fcd217219b43c5a52b102cd210e1f93b440b96400ba0001cd21b43ecd21 }


condition:
	$a0
}