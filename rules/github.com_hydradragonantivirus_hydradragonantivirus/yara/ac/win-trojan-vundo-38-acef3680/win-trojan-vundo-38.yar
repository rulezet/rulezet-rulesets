rule Win_Trojan_Vundo_38
{
strings:
	$a0 = { 60e80f160000769982190000869202e8 }


condition:
	$a0
}