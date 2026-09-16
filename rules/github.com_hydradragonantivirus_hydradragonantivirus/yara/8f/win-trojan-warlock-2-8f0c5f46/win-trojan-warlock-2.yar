rule Win_Trojan_Warlock_2
{
strings:
	$a0 = { cd21c3a20801e8e0ffb440b9dc02ba0000cd21e8d3ffc33dffff750a81fa4c577504b84b4fcffa }


condition:
	$a0
}