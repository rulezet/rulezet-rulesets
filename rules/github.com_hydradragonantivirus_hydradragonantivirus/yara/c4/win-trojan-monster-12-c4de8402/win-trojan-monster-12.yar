rule Win_Trojan_Monster_12
{
strings:
	$a0 = { 01bedc2c8034cd46e2fa25cdcd934e23ce0b89c13326cd0b89c1cd2544cc474912cc6fcdcc46492dcc6ecccc75e9 }


condition:
	$a0
}