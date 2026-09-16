rule Win_Downloader_Banload_1064
{
strings:
	$a0 = { cfa543f78b8ac9ecc04f32737b704083c842a4eae94a4fe611f475b3e8a71df975b6398ecfbeadcb738aea292f0d206ccdf6d6c3302e456b41972e4864e2112e200e41406feffd21229b604415e2 }


condition:
	$a0
}