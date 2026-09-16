rule Win_Trojan_Anthrax_4
{
strings:
	$a0 = { 1f32f6b9020033dbb80202cd13e9eefe }


condition:
	$a0
}