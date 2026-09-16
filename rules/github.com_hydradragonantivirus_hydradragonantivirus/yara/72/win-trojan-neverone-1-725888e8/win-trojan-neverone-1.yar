rule Win_Trojan_Neverone_1
{
strings:
	$a0 = { 578db616018dbe1601b9c000fcad352f43abe2f95f5e5958c3e8e1ffcd21e8dcffc3 }


condition:
	$a0
}