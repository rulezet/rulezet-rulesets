rule Win_Trojan_Lapidari_1
{
strings:
	$a0 = { 7304b02aeb02b0023e8886f5038d8ec1038d8610018bf02bc83e8aa6fd038bfeac02c4aae2fa }


condition:
	$a0
}