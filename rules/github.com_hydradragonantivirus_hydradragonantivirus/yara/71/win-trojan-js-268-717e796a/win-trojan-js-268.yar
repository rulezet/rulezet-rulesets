rule Win_Trojan_JS_268
{
strings:
	$a0 = { 7372633d687474703a2f2f6d6d2e616138383536372e636e2f696e6465782f6d6d2e6a73 }


condition:
	$a0
}