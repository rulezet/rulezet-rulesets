rule Win_Downloader_Agent_31743
{
strings:
	$a0 = { 684000004041413bc672bfeb4933c0be0001000083f841721983f85a77148088 }


condition:
	$a0
}