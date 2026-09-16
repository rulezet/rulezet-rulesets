rule Win_Trojan_UpDown_1
{
strings:
	$a0 = { 7bab02ac0b465aa63a7e43795e87393149786440edb8f37829465a303bba6c416c4a069a8929454b }


condition:
	$a0
}