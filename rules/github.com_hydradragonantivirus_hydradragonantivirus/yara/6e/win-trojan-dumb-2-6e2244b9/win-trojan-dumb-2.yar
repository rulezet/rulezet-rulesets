rule Win_Trojan_Dumb_2
{
strings:
	$a0 = { 0300b440c35dbf00015781ed06018db61d01a5a48d96dc01e8d8ffb44e8d9620012bc9888e0602 }


condition:
	$a0
}