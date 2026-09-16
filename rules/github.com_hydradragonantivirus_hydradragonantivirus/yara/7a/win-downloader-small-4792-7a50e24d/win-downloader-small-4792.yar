rule Win_Downloader_Small_4792
{
strings:
	$a0 = { 40008d0c885150e8b5ffffff5959c38b4424040faf442408506a08ff152010400050ff151c104000c3ff25a8104000ff2570104000ff256c104000cccccccccccccccccccccc }


condition:
	$a0
}