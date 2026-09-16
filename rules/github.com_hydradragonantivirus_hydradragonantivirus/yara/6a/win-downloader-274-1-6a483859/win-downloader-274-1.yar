rule Win_Downloader_274_1
{
strings:
	$a0 = { d6c9bc29ba4e9c04b4c9497af677b337d7fb5bcd3acd7ce648e975f5ccfb020121d7d30a0dd559d98161afe2fbe531b1c23755b90245dbc6715f55d5dbdbe2e1fe91fdbf5c1c1b8b3f17b698c3da }


condition:
	$a0
}