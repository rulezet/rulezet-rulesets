rule Win_Trojan_Fall_2
{
strings:
	$a0 = { 4a0674352ec606560626b8024233c999cd21a301052d0600a35406b440ba0005b95401cd21b8 }


condition:
	$a0
}