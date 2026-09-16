rule Win_Trojan_DiskKiller_1
{
strings:
	$a0 = { a113042d08002ea31304b106d3e08e }


condition:
	$a0
}