rule Win_Trojan_Mindless_1
{
strings:
	$a0 = { b9eb09b805feebfc80c43bebf41e2bc050b42acd213c00756fb8013332d2cd21b9460090be1d02bf63028a04a2a9028036a90201a0a90288054647e2ed }


condition:
	$a0
}