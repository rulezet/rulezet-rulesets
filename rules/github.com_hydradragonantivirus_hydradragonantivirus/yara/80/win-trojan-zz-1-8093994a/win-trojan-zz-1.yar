rule Win_Trojan_ZZ_1
{
strings:
	$a0 = { 1e06e800005eb85a4dcd213d4d5a744e8cd8488ed8a103002d1b00a303008cdb03d8438edbc60600005ac706010008 }


condition:
	$a0
}