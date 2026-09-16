rule Win_Trojan_Emulator_1
{
strings:
	$a0 = { b440b9f7008d960301cd21582d0300c686fa01e98986fb01b8004233c999cd21b440b90300 }


condition:
	$a0
}