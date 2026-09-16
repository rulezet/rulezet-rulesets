rule Win_Trojan_Lewd_4
{
strings:
	$a0 = { 500633c08ec026a184002ea3140626a186002ea316 }


condition:
	$a0
}