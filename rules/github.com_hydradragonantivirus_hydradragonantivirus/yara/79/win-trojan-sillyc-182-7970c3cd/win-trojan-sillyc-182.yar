rule Win_Trojan_SillyC_182
{
strings:
	$a0 = { 72eeb440b94501ba0001cd2172e2b802422bc92bd2cd2172d7b440b91b00ba450203164102cd }


condition:
	$a0
}