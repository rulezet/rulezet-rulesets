rule Win_Downloader_Small_2627
{
strings:
	$a0 = { 89c05189d20f3189c98d360fa289ed87ed8d3629c087c987ed87c95989c989f687c9e2dc89f68d3687db5887dbffe0 }


condition:
	$a0
}