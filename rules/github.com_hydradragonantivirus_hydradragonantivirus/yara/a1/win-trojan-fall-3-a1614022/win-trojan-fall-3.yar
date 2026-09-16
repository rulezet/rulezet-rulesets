rule Win_Trojan_Fall_3
{
strings:
	$a0 = { 06680626b8024233c999cd21a301052d0600a36606b440ba0005b96601cd21b8004233c999cd }


condition:
	$a0
}