rule Win_Trojan_Jocker_1
{
strings:
	$a0 = { 4a8ec28cda4a8eda5a9026a10300 }


condition:
	$a0
}