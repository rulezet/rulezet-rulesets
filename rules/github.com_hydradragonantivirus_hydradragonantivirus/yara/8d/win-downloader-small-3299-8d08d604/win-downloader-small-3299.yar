rule Win_Downloader_Small_3299
{
strings:
	$a0 = { 4af8545576311b43811a61400cb5d364f8f579604a4acdce424ed530d738790d41292343daa2f2ac5a874adba17d6f8f5f65cca08855c1bc5e45 }


condition:
	$a0
}