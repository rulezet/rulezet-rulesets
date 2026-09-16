rule Win_Trojan_Delf_588
{
strings:
	$a0 = { 95bcedffff8b07e8501effff8b95bcedffffb8a03c4100e89cfdfeff }


condition:
	$a0
}