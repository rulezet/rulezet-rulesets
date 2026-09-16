rule Win_Trojan_Sahand_3
{
strings:
	$a0 = { 2be7f42a702732582ba22c7803ef07e80de736307c927d5e4884385925f7669c806ca6192921b62b }


condition:
	$a0
}