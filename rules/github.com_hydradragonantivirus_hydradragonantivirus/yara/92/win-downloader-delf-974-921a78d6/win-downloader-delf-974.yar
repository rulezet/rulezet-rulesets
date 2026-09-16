rule Win_Downloader_Delf_974
{
strings:
	$a0 = { 8a2066b640fe76844e89c0f8993a6dd22f5da179dbbeb422579d3d7eb6f725d89649b1dd39c2cee002967e6feeee0c25ea49bd5d6186a785b8dfd5b9c08c863cdb50c131a2d1 }


condition:
	$a0
}