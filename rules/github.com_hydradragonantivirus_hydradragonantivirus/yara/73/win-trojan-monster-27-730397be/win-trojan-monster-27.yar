rule Win_Trojan_Monster_27
{
strings:
	$a0 = { 02bede2cfc300446e2fb26eb96ed8082839e99889fed9091cde7e3e7cde7e38e8280cd0ba4d82400e6cde2d9 }


condition:
	$a0
}