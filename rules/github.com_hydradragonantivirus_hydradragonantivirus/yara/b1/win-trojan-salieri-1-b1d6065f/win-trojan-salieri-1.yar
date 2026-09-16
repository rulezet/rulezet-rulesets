rule Win_Trojan_Salieri_1
{
strings:
	$a0 = { 01012da70133d2bb1000f7f30511008ccb03c350b8c00150cb2ec706e9056600eb072ec706e9057b002e8c1e0f }


condition:
	$a0
}