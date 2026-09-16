rule Win_Downloader_Small_3439
{
strings:
	$a0 = { 3c2e1525b063c0215805ff1424101f5ed9d673066e10c222573b7f1edac8dd565e6e7890a92ca8ad832ad28fb5de953e6cd4bedbf3e563a8c32507bc5079f388d775b7a8e21df46f4a745db7f2fb7a87 }


condition:
	$a0
}