rule Win_Spyware_Banker_2414
{
strings:
	$a0 = { 07f3e9e7cca77942fb6d5335ebb718356b228a229d64443fff32d47b4a167d05c73687e2e19d5d6b0bdc230f78e0fb80067409a6cb5b85a64fd3d387a2d384dec0ad87820fb41fd6a921 }


condition:
	$a0
}