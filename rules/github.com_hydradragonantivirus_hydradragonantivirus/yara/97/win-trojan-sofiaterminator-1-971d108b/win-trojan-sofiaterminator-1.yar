rule Win_Trojan_SofiaTerminator_1
{
strings:
	$a0 = { 590529d2e8480039c87401f9c3b42ce83d0080fe05771729c02ec606390000ba8000cd138a }


condition:
	$a0
}