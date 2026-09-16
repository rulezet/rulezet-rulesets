rule Win_Trojan__0511_0001_000_1
{
strings:
	$a0 = { f3a4b8004233c999cd21b4408d96a10359cd21fe8ea003e9edfeb801438d969303cd21c35bb440 }


condition:
	$a0
}