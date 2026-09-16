rule Win_Downloader_Delf_968
{
strings:
	$a0 = { b8c89f1ee722dd0a69fd6f2ac53586e177cbcfcf3065e313bac31ffda4c637e8f0e1562da52c3417ed9ab439af538928f5072ee842d4737ae938dcd2f99e68104442333b8975 }


condition:
	$a0
}