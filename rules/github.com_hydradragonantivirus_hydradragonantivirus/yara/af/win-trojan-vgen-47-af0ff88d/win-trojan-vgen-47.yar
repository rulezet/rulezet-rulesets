rule Win_Trojan_VGEN_47
{
strings:
	$a0 = { e800005b83eb038beb35000150b909008bf381c60401bf0001f3a4b41a8d96d900cd21b44e8bd581c2d300b90300cd21 }


condition:
	$a0
}