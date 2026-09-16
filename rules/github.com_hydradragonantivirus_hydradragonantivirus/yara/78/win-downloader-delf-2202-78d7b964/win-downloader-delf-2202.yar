rule Win_Downloader_Delf_2202
{
strings:
	$a0 = { ea173e479f36ab3840a8600a20ed3693487bf4d7615afc8ce602f9981e065e1a21ffcf91d871eb816cb048fe33ec4b75297351e32a3ad5b2249c39cb68d4da61c6f47fec8bdd32e15c9aeff6f164282d }


condition:
	$a0
}