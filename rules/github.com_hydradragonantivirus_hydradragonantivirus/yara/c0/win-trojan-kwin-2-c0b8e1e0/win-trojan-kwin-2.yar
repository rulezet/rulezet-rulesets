rule Win_Trojan_Kwin_2
{
strings:
	$a0 = { 62ffffebe58be55dc30000000000ffffffff0a0000007379733978312e6578650000558bec81c4e4fbffff33c9898de8fbffff898de4fbffff8955f88945fc8b45fce83f6cffff33c0556880 }


condition:
	$a0
}