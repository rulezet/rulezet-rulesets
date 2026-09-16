rule Win_Downloader_Small_3210
{
strings:
	$a0 = { 8b945162a472decb4d4d18b6efcc7b41788dfb2b678dea3a3d7f947444bf906c328d7df7b1c4f00b3a7c90724b9ff6643400b16ff86650fe778cf54d5a7c906f327cf76e587a }


condition:
	$a0
}