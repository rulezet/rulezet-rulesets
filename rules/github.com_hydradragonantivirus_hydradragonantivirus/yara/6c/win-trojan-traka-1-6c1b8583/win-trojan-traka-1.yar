rule Win_Trojan_Traka_1
{
strings:
	$a0 = { b90500ba8d03cd21e97f00bf7400a5a5be1408a5a5bf1808b87454abb002e894005052b90002 }


condition:
	$a0
}