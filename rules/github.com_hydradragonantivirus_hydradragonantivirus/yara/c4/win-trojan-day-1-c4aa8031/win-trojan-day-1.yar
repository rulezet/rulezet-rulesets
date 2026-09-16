rule Win_Trojan_Day_1
{
strings:
	$a0 = { 8e062c00b90010fc33ffb050f2ae7518b64126383575f347 }


condition:
	$a0
}