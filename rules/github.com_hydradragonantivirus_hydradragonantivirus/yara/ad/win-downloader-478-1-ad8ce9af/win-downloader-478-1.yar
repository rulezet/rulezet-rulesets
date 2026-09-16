rule Win_Downloader_478_1
{
strings:
	$a0 = { 65c1d91d978de6ddf3a5c7dd19a8b424adebadd77af76be8f02a88f8608502d78ac856d97163a99d70654f41ce97abe6fe8039abe8ca187134e6ebd991faa43c02f5114af158d672a58b0ec563ce }


condition:
	$a0
}