rule Win_Trojan_ScreamF2B_1
{
strings:
	$a0 = { 3dffff75039d40cf80fc3d741180fc4b741a80fc43 }


condition:
	$a0
}