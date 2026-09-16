rule Win_Trojan_Monster_40
{
strings:
	$a0 = { d72ccdeb00745902bee32c8034cd46e2fa26e996ed8082839e99889fed9091cde7e3e7cde7e38e8280cd14bbd824 }


condition:
	$a0
}