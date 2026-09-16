rule Win_Trojan_Crypt_146
{
strings:
	$a0 = { 81c3????????(01|29|31)(18|19|1a|1e|1f)81eb[0-20]3b(c3|cb|d3|eb|f3|fb)0f82??ffffff }


condition:
	$a0
}