rule Win_Trojan_Bat2Exec_2
{
strings:
	$a0 = { 27ce1d3cb9999a5773951a567a382b263d244862662b2725e060340b670442917e2c397099 }


condition:
	$a0
}