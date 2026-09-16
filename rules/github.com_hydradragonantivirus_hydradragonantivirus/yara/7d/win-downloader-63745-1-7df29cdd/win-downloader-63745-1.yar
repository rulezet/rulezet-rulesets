rule Win_Downloader_63745_1
{
strings:
	$a0 = { e8050078c2e9050020398bff558bec81ec28 }

	$a1 = { 64656c }

	$a2 = { 6f70656e }

	$a3 = { 68740000747000003a2f }


condition:
	$a0 and $a1 and $a2 and $a3
}