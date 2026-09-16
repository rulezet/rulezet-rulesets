rule Win_Trojan_Thunder_1
{
strings:
	$a0 = { 8f02bcc87fd0a25b7052744bbab670b59ad157bc74288d8367a5246755890a7c9236e34e1cfbd15e }


condition:
	$a0
}