rule Win_Trojan_USSR_11
{
strings:
	$a0 = { 0157b9705a8b55facd21b43ecd21b801435932ed8bd7cd21 }


condition:
	$a0
}