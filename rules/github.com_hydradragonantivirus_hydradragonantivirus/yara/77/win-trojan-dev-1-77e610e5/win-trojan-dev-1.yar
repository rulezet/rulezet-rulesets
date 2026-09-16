rule Win_Trojan_Dev_1
{
strings:
	$a0 = { 9e00b8023dcd217213909093b98a00ba8a01b440cd21b43ecd21ebd8cd203f3f3f3f3f3f3f3f }


condition:
	$a0
}