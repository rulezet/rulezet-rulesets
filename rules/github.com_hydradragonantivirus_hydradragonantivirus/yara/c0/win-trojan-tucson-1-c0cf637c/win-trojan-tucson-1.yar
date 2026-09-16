rule Win_Trojan_Tucson_1
{
strings:
	$a0 = { 0190e800005d81ed0701e84f018db68502bf000157a5a5b419cd213c017701c38d968f02b41acd21b44e }


condition:
	$a0
}