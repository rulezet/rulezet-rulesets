rule Win_Trojan_SillyORCE_11
{
strings:
	$a0 = { c906518ec1bfb00426390d751dbe0001b14cfcf3a4eacb0400008ed9b8dc0487068400ab9187068600abcb80fc4b75 }


condition:
	$a0
}