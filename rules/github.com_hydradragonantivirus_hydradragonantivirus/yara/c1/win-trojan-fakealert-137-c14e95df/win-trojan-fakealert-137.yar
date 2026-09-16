rule Win_Trojan_Fakealert_137
{
strings:
	$a0 = { 5390905790909090905690e8eaffffff90906a009090e8d3ffffff83e8579090908db8719f40 }


condition:
	$a0
}