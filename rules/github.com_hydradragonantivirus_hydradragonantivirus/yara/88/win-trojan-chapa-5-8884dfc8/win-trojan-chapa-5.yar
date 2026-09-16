rule Win_Trojan_Chapa_5
{
strings:
	$a0 = { 7c014d567429e869ff2ec606130000b440b936020e1f33d20ee83dffe85fffb440b93602ba00bf }


condition:
	$a0
}