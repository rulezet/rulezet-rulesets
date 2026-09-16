rule Win_Trojan_VGEN_289
{
strings:
	$a0 = { 8b5db633d28eda3b5d5e7454b280b408cd13724c0652b413cd2ffc0633c08ec0e66193ab58ab8bc18ae9b106d2 }


condition:
	$a0
}