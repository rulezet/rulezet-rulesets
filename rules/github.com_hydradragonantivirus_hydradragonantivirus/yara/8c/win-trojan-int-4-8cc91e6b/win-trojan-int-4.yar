rule Win_Trojan_INT_4
{
strings:
	$a0 = { 8ec026a14c002ea3760126a14e002ea37801b413cd2f1e52b413cd2f5a1f33c08ec02689164c }


condition:
	$a0
}