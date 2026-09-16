rule Win_Trojan_SillyRC_41
{
strings:
	$a0 = { 8ec3bf9002fab141f3a4a674124e4fa456be84005626a526a55fb029abab5e5f2bce0e07f3a4c380fc407513608b }


condition:
	$a0
}