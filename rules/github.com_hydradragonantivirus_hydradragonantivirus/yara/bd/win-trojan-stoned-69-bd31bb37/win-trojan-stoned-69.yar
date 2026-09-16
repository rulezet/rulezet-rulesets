rule Win_Trojan_Stoned_69
{
strings:
	$a0 = { 0102cd13730632e4cd13ebf3be0200bf027cb91c00fcf3a4be0002bf007eb94e00fdf3a426c706 }


condition:
	$a0
}