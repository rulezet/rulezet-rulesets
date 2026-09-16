rule Win_Trojan_Mainman_3
{
strings:
	$a0 = { 5dba4500b9380001ca81ed0601b90300bf50018db6060283ef5057f3a4e8b400b71a8d9650028ae7cd21e89c00b74e8a }


condition:
	$a0
}