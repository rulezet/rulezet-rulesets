rule Win_Trojan_Ylang_2
{
strings:
	$a0 = { cc2b90e7f0df52216021e396a9609162d547cc2b93faefdf4c42aaaaaaaaf72b4795baeaaa252fc6beeaaa2b2fc6beeaaa79acaaaa21e896a96821ead2 }


condition:
	$a0
}