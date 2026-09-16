rule Win_Trojan_PSMPC_2
{
strings:
	$a0 = { 515256571e063d004b740e071f5f5e5a595b589dea }


condition:
	$a0
}