rule Win_Trojan_Monster_21
{
strings:
	$a0 = { 02bedc2c8034cd46e2fa26e896ed8082839e99889fed9091cde7e3e7cde7e38e8280cd3699d42400e6cddfd539cb }


condition:
	$a0
}