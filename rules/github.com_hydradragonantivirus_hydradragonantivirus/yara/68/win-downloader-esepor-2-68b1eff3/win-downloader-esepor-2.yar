rule Win_Downloader_Esepor_2
{
strings:
	$a0 = { 636b796f757273656c661b571fbe6dff20637275746f707a750967692d626d6dbbdd5c2f75722f556f696d6c2e0dc212d614004b2f64adc59eaf }


condition:
	$a0
}