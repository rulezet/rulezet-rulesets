rule Win_Trojan_Trivial_376
{
strings:
	$a0 = { cc2bce0e07f3a4c380fc3c751fcdc050938bf24ead3d6f6de0f9750b1e0e1fb440b15099cd211f }


condition:
	$a0
}