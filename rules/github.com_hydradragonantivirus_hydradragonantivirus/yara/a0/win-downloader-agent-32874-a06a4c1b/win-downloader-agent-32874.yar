rule Win_Downloader_Agent_32874
{
strings:
	$a0 = { e4af210169dc5eb9634b3fa4b5b7299370621d81aaf5d803207b0da2191d16889dcc7ff0f14cb5f41db7ada2dd5fb00bf49d32a8374b5b11eac90322bdea }


condition:
	$a0
}