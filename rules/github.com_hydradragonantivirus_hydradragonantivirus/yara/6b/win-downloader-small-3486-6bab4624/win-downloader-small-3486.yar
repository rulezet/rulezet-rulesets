rule Win_Downloader_Small_3486
{
strings:
	$a0 = { 015d0ab7abedcd3dab6f53ea0c9bd9f92c1bc81bcb48e33770baba7a0e1f6df60489129e7242334f77c860ce54503b2583de7631d0372138cb89e67c661add054390010eb8f1b79ccdc5d1929a44 }


condition:
	$a0
}