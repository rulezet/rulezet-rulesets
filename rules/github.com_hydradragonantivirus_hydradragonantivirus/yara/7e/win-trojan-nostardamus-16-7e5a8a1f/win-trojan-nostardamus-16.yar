rule Win_Trojan_Nostardamus_16
{
strings:
	$a0 = { 02eb00fa06fb804506028ed9c43e0400b0cfaae42150b0ffe62158e621b9eb09b82d2debfc80c4bdebf4cd21 }


condition:
	$a0
}