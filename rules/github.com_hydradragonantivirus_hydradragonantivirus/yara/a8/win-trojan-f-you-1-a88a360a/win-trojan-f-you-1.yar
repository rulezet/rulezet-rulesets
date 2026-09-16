rule Win_Trojan_F_You_1
{
strings:
	$a0 = { c135ffff587402ffe0e974ffb00233d233c9b442cd }


condition:
	$a0
}