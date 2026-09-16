rule Win_Trojan_Monster_42
{
strings:
	$a0 = { 864914ae0d0c874916af0f0cb52928b75e0f0edbc02c8749103d89500f5bb94a3fdf8ccb660fc02c }


condition:
	$a0
}