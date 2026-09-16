rule Win_Trojan_Tucson_2
{
strings:
	$a0 = { eb0190e800005d81ed0701e84f018db68b02bf000157a5a5b419cd213c017701c38d969302b41acd21b44e8d968f02 }


condition:
	$a0
}