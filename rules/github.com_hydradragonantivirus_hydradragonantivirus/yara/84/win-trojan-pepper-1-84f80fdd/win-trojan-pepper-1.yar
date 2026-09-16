rule Win_Trojan_Pepper_1
{
strings:
	$a0 = { 4f4d00b41aba800090cd2106b84000908ec026803e6c0002077317b42acd2180fa01740efe }


condition:
	$a0
}