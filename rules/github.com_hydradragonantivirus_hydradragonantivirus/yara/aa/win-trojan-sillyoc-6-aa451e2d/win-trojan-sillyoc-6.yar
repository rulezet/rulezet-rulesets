rule Win_Trojan_SillyOC_6
{
strings:
	$a0 = { 0e01b95c0080375543e2fabe0001c7049090be0e01bf6901b95c00f2a4bb6901b95c0080375543e2fab44eba63 }


condition:
	$a0
}