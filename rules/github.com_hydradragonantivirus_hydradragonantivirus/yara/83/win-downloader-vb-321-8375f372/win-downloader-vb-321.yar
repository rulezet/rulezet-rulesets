rule Win_Downloader_VB_321
{
strings:
	$a0 = { 8d55b48d45b852506a02ff15bc10400083c40c8d9564ffffff8d4d84c7856cffffff1c184000c78564ffffff08000000ff15d8104000 }


condition:
	$a0
}