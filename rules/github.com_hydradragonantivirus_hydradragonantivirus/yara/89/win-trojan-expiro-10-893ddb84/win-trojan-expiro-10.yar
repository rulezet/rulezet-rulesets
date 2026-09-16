rule Win_Trojan_Expiro_10
{
strings:
	$a0 = { 60e8cb48020061e9 }


condition:
	$a0
}