rule Win_Trojan_Simbioz_5
{
strings:
	$a0 = { 0901e80f0090cd2076697269692072756c657a242e892efe005d83ed03601e06e800005e83ee0f2e8aa44901b0b42e }


condition:
	$a0
}