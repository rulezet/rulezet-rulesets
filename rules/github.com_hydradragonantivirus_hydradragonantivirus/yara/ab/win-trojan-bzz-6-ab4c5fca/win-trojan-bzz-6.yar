rule Win_Trojan_Bzz_6
{
strings:
	$a0 = { 408b0eef0381c1b702bac303cd21b80042e83500b440b90300bab603cd218b0ebf038b16c103b8 }


condition:
	$a0
}