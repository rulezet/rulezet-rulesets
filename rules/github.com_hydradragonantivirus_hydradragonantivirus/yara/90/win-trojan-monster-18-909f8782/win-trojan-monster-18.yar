rule Win_Trojan_Monster_18
{
strings:
	$a0 = { 02bede2c8034cd46e2faeb2496ed8082839e99889fed9091cde7e3e7cde7e38e8280cd14bbe72400e6cdfde659dd }


condition:
	$a0
}