rule Win_Trojan_Pet_1
{
strings:
	$a0 = { 71019a00000f015589e5b800049a7c02710181ec0004e842fc8dbe00ff165731c0509a0a0d7101bfc6041e57bf }


condition:
	$a0
}