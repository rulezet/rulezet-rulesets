rule Win_Trojan_Hates_1
{
strings:
	$a0 = { e84e00b90300b4408d96d601cd21b002e83e00b440b9d4008d960301cd21eb08b43ecd21b44f }


condition:
	$a0
}