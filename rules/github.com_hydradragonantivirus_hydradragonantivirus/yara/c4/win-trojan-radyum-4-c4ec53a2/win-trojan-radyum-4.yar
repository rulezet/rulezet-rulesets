rule Win_Trojan_Radyum_4
{
strings:
	$a0 = { b9a60181372c3b83c302e2f790c43b2c66add6373a1ffba2e3e83dbc3b02b7aa652815a5bd4c3fa1adac39a52d }


condition:
	$a0
}