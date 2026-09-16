rule Win_Trojan_Vgen_138
{
strings:
	$a0 = { 0300cd10ba0c01b409cd21b8070ccd213c3172f73c3477f32c3132e403c003c005b8029353ba1202b409cd215b8b0f }


condition:
	$a0
}