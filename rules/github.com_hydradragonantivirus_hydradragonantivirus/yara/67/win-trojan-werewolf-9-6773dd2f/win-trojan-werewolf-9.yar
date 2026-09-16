rule Win_Trojan_WereWolf_9
{
strings:
	$a0 = { cd200e170e070e1fe89402e8a2020e178cc00510002e0106d2002e0306d600501e060e07bfd7025733d2528edac5 }


condition:
	$a0
}