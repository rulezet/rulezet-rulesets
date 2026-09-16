rule Win_Trojan_LdPinch_6
{
strings:
	$a0 = { bf237f3bbf2363dbcf236f3bbf2338c3e7236f3bbf2338c3ef23273bbf2338c39f235f3bbf237f3bbf23373bbf23cdc32723173bbf236cc32723373bbf237f3bb723453bbf2338c3 }


condition:
	$a0
}