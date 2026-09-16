rule Win_Downloader_Delf_966
{
strings:
	$a0 = { a1f6f2a2f4f6625c36f754396bf9e3c3339f20bc1caf413210a61f8fc1efd96991d7a9e22f66588e7c4c5db5f327c6c87292bb5231f0b28eb8fdeae37015ae95e092adcee615 }


condition:
	$a0
}