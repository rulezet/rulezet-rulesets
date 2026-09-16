rule Win_Trojan_Tony_5
{
strings:
	$a0 = { 8cc880c4108ec0be000133ff8bcef3a4ba0001b41accb4 }


condition:
	$a0
}