rule Win_Trojan_Zachpast_20
{
strings:
	$a0 = { 406d6d653d5669727573736564 }

	$a1 = { 2e696e690d0a6e323d536b6572722e646c6c }


condition:
	$a0 and $a1
}