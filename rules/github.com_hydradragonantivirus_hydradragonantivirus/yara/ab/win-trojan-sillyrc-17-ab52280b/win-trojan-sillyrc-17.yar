rule Win_Trojan_SillyRC_17
{
strings:
	$a0 = { b8023dcd6172748bd833c08ed8b43fbaef02b9ef00 }


condition:
	$a0
}