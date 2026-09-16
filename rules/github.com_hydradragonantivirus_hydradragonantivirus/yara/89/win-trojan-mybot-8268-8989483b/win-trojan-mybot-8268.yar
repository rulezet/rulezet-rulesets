rule Win_Trojan_Mybot_8268
{
strings:
	$a0 = { a3ccc88b3bb6fbd2af57c6259d5eaf90f3ffcc6341d2e20f51f7750eeb5066683cc9a8e3dd0db87efdd191e630aabe68edec0db4427e812c5de385ec10fd918edda071789b9e }


condition:
	$a0
}