rule Win_Trojan_Gandalf_1
{
strings:
	$a0 = { bb0001877701bfaefdb9d60003f3fc57f3a5c3e8c700 }


condition:
	$a0
}