rule Win_Trojan_Nguyen_1
{
strings:
	$a0 = { 5dbe290129f501ee2e813c4d5a74072e813c5a4d75302e8c9637012e89a639010e17bccc0e }


condition:
	$a0
}