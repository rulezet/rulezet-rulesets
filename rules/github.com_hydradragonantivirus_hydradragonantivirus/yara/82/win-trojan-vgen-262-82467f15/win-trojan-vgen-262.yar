rule Win_Trojan_VGEN_262
{
strings:
	$a0 = { be000103d087d18b1ce8000086d6e20233cb13ce23de031d134d0223de2e8a048bcb8bd08bca34be031d134d0204 }


condition:
	$a0
}