rule SecuDE_random_add__32_big_32_
{
strings:
	$a0 = { 23571113171921232931374143475359456fbcae456fbd67245fbcdd43563567 }

condition:
	$a0
}