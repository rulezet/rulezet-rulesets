rule Win_Trojan_Monster_26
{
strings:
	$a0 = { 02bedc2c8034cd46e2fa26eb96ed8082839e99889fed9091cde7e3e7cde7e38e8280cd0ba4ef2400e6cde2eecdcd }


condition:
	$a0
}