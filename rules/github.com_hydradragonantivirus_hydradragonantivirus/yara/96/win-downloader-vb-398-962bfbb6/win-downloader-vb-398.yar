rule Win_Downloader_VB_398
{
strings:
	$a0 = { 423260c123ca2585e7489f8e59fa6ab62b8cb9ddd65950f0ae36a0298b65bb504ef5f3efaf63cbd98928d703a35341e3c0004f27699068c64b10d9314ffaad388a }


condition:
	$a0
}