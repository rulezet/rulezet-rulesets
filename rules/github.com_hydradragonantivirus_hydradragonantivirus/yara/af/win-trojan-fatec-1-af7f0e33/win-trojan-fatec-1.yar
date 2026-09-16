rule Win_Trojan_Fatec_1
{
strings:
	$a0 = { b440b9f4018d960c012efe8e0d02cd21e873002efe }


condition:
	$a0
}