rule Win_Trojan_Dutch_Tiny_6
{
strings:
	$a0 = { 81ee0b018bac380281c50301e80200eb3f505351568b9c3a0281c65c018b0e1000d1e973014e89f7ad31d8abe2fa5e }


condition:
	$a0
}