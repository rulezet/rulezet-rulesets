rule Win_Trojan_FSN_1
{
strings:
	$a0 = { 268b1e17008b16030183ea03b9f70490cd21b440268b1e17008b3603018d5406b90300cd211f }


condition:
	$a0
}