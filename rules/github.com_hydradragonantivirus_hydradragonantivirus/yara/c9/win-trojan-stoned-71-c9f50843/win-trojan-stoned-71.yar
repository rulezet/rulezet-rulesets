rule Win_Trojan_Stoned_71
{
strings:
	$a0 = { 02b90800890e8c01b80103ba8000cd137214be9203bf9201b97000f3a4b8010333dbfec1cd13 }


condition:
	$a0
}