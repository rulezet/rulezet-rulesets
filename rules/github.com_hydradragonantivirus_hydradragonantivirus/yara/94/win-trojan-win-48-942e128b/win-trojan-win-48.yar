rule Win_Trojan_Win_48
{
strings:
	$a0 = { bf010bc07533e8e800bb2501b84000b90100e8ed010bc075208b1e2501b90008bab702e88d010b }


condition:
	$a0
}