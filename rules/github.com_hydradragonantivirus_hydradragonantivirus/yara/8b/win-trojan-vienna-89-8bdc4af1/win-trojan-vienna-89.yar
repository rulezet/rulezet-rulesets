rule Win_Trojan_Vienna_89
{
strings:
	$a0 = { cd21722133c933d2b8420086e0cd217214b90300817cfe00027603b966068d540db440cd218b }


condition:
	$a0
}