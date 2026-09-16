rule Win_Trojan_Happinez_1
{
strings:
	$a0 = { 1cc3bb7f0803dfffd3e8eeffb440becd0803f78b0c8bd781c20001cd21bb7f0803dfffd3c3 }


condition:
	$a0
}