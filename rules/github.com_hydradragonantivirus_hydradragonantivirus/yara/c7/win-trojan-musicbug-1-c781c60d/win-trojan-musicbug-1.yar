rule Win_Trojan_MusicBug_1
{
strings:
	$a0 = { fcf3a506b8000250cb505351522ea3 }


condition:
	$a0
}