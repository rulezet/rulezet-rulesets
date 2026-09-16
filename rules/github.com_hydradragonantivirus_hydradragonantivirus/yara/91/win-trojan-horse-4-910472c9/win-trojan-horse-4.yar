rule Win_Trojan_Horse_4
{
strings:
	$a0 = { a300018b4602a30201b800018ccaeb }


condition:
	$a0
}