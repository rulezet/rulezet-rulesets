rule Win_Trojan_Flip_9
{
strings:
	$a0 = { bb4ff61fb98c9bb2d081c1536deb03616d610097bd0943eb }


condition:
	$a0
}