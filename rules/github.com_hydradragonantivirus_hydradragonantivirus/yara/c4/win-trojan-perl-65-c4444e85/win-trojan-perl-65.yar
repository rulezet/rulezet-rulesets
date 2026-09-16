rule Win_Trojan_Perl_65
{
strings:
	$a0 = { 7072696e742066696c652040736f6c76657465633b }


condition:
	$a0
}