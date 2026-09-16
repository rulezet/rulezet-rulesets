rule Win_Downloader_Small_1815
{
strings:
	$a0 = { 6874e270383a2fb377022efb64906e3231ef438174fef4c518785f1b1120296e663df3d03a5c62f5ec742efc6c53644982676f62 }


condition:
	$a0
}