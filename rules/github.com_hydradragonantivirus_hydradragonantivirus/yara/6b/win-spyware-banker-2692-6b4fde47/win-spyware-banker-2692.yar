rule Win_Spyware_Banker_2692
{
strings:
	$a0 = { b0aa248711bcb9c39822edb01c5dfde9a984c758c996d7dbf4c5fd04b2449ab72a25acdf5fb7889b6d2df8ead917377440b73633f1a88c2ea3a7c706c7bf2a751cd4e5ddafb11956daad72ff9020 }


condition:
	$a0
}