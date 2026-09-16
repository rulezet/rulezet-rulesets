rule Win_Trojan_Mybot_8262
{
strings:
	$a0 = { 2c4829cc07b3b3afc243d61ffd1018032907583ec3a4f1ffaa2e306a9f61c90252935a81ba65ba7fc12f4307d7cdd052dc0179eeec16b53c423ed1e79eabb64e865385b6d821 }


condition:
	$a0
}