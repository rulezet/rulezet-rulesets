rule Win_Adware_Lop_196
{
strings:
	$a0 = { 86b6f3f03e82c45ec8159ebbad3b686c9f15dc4eca56d39fdd00856b5f66dcd3c699723acf9a5cf90b864282d39863fece29520451f787357773a617 }


condition:
	$a0
}