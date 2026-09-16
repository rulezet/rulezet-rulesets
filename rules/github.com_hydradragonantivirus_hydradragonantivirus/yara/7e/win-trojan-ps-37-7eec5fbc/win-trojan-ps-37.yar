rule Win_Trojan_PS_37
{
strings:
	$a0 = { bb1b002e8107181e4343e2f7d0e2e83e69cffae206e8f600f6e87598b2e375a0aae38d878d87ae685be5ea95026f7e2aebae09 }


condition:
	$a0
}