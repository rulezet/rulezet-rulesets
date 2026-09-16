rule Win_Downloader_Small_2041
{
strings:
	$a0 = { 5c7a62f7bf48156c64408d7702fd65fb906e3231ef43c174f8666c613b7368306d20 }


condition:
	$a0
}