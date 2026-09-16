rule Win_Trojan_Gen_159
{
strings:
	$a0 = { 02bf78020e57e812ffbf80020e57e80affbf8a020e57e802ff8dbe00ff165731c0509a5806 }


condition:
	$a0
}