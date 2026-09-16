rule Win_Trojan_DVC_2
{
strings:
	$a0 = { 5d81ed0a01fcbe030103f5bf4c0203fdb90300f3a6741abe030103f5bf0001b90300f3a4b9000151be8000bf00 }


condition:
	$a0
}