rule Win_Trojan_SillyORC_3
{
strings:
	$a0 = { fecd2180fc52741bb82135cd21891e77018c067901ba2b }


condition:
	$a0
}