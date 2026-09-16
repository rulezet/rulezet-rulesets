rule Win_Downloader_1593_1
{
strings:
	$a0 = { e8f7fafeffb806000000e8fdfbfeff8bd885db750fb88c584100ba00304100e8780cffff83fb01750fb88c584100ba??304100e8640cffff }


condition:
	$a0
}