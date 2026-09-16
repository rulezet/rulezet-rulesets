rule Win_Trojan__0557_0004_001_1
{
strings:
	$a0 = { 21e4403e88863101b4408d960301b92f00cd218dbe9c02578db63201b96a0151e8adfeb440595a }


condition:
	$a0
}