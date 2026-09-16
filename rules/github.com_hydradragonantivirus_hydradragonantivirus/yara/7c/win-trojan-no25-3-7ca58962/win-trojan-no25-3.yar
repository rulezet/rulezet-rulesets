rule Win_Trojan_No25_3
{
strings:
	$a0 = { 4ce9067251a2994c9d0e76d96762fe4c9d7ce965a1984ceb44e2654cee74e0656c75debd6b998a51 }


condition:
	$a0
}