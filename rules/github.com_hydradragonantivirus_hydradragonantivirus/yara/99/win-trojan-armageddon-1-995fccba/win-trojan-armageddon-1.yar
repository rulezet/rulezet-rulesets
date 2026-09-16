rule Win_Trojan_Armageddon_1
{
strings:
	$a0 = { b93b008d94f400cd218d942002b9f101b440cd21e4408ac832ede44032c8e5408bd0e54033c2 }


condition:
	$a0
}