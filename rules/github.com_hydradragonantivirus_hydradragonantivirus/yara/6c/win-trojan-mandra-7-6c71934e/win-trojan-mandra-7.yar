rule Win_Trojan_Mandra_7
{
strings:
	$a0 = { c149bc774dbfa6aabc4b54dfc17767bf72fe8bdf1dc5e48503d3bebee48503d5bebe72fe4b54b1c0 }


condition:
	$a0
}