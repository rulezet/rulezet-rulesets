rule Win_Trojan_Queeg_1
{
strings:
	$a0 = { 1daaab840f3ebd3db1981c34b14a85c8dadff92a9cd0812f1d }


condition:
	$a0
}