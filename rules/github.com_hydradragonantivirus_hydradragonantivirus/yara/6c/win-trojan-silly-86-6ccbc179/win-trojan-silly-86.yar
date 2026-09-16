rule Win_Trojan_Silly_86
{
strings:
	$a0 = { 2e7068697368636f702e6e65742f }

	$a1 = { 47455420257320485454502f312e310d0a4163636570743a202a2f2a }


condition:
	$a0 and $a1
}