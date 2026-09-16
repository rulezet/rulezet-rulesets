rule Win_Trojan_VGEN_531
{
strings:
	$a0 = { cd2159b80143ba80fdcd210e1fb4098d96ff02cd21e9a201b41aba00fdcd21b44e8d96b90433c9cd217303e98c01b8 }


condition:
	$a0
}