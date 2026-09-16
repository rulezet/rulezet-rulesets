rule Win_Trojan_Bancos_1320
{
strings:
	$a0 = { f249d6f12796d4725db125deb70272390dcd3b0abb24f912a817aa2cb948811fc982565fec9177c5c4d272c10ebfe005d0d881e5c69bd44ffa82cc6a377a77f7ceac79af9ab34a59c5f3c210f391c85a2ba3 }


condition:
	$a0
}