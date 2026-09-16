rule Win_Trojan_Hupigon_105
{
strings:
	$a0 = { 68a1294a006aff6a00e8e74ef6ff8bd885db741ee82c50f6ff3db70000007512 }


condition:
	$a0
}