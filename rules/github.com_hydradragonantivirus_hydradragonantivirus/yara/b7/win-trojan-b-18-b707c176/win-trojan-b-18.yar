rule Win_Trojan_B_18
{
strings:
	$a0 = { 7420503d005774d780fc3f749a53 }


condition:
	$a0
}