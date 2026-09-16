rule Win_Trojan_Austr_5
{
strings:
	$a0 = { 023dba9e00cd218bd8b905008d962101b43fcd2189d6ad }


condition:
	$a0
}