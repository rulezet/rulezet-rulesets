rule Win_Trojan_Deviant_4
{
strings:
	$a0 = { ed090150558becc74602fe005d8dbe4d01b9ca018aa61803478a0532c48805e2f733f65e81fefe00741981feff00 }


condition:
	$a0
}