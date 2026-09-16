rule Win_Trojan_Mybot_8336
{
strings:
	$a0 = { a4ab87ad4ea3b4f43ce68c52c48bf87e6c83b48de5c096de58f9b8a1380f28bbd161118adaea4791f3119ef81ed2ad489639f3161ad05d80714d3069db1daafb3d42285df03af0424a1d156267b7e770 }


condition:
	$a0
}