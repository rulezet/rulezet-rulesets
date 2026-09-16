rule Win_Trojan_Diple_2
{
strings:
	$a0 = { 558bec81ecdc0100006aff6aff6affff15????420085c0752f6a016a006a016a016a03ff15????420085c0753ab8????40008d040255506a056a00ff15????42 }


condition:
	$a0
}