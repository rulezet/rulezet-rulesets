rule Win_Trojan_VGEN_558
{
strings:
	$a0 = { 21b800429933c9cd21b440b91c00ba3f03cd21e930ff5b42575d00476f6f626572202863292062 }


condition:
	$a0
}