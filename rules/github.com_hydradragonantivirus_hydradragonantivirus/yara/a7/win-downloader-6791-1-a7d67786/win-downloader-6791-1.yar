rule Win_Downloader_6791_1
{
strings:
	$a0 = { 0bc0750d68dc884000ff75ece8930700000bc0750d68e4884000ff75ece882070000 }


condition:
	$a0
}