rule Win_Trojan_Trojan_217
{
strings:
	$a0 = { b9eb00810722364343e2f8c6cade265fb7efc9e4e7960b2297ff06311a520a6aa22658b64d0ccdde0961f8f0c9 }


condition:
	$a0
}