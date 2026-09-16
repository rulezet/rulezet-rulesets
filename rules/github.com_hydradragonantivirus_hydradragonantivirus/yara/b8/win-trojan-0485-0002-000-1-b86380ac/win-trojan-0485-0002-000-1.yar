rule Win_Trojan__0485_0002_000_1
{
strings:
	$a0 = { f3a4b8004233c999cd21b4408d96a40359cd21fe8ea303e9edfeb801438d969603cd21c35db440 }


condition:
	$a0
}