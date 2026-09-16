rule Win_Trojan_Terminator_3
{
strings:
	$a0 = { 1e9c8ccb8cd93bd97403e96601b400b280cd139d1f075f }


condition:
	$a0
}