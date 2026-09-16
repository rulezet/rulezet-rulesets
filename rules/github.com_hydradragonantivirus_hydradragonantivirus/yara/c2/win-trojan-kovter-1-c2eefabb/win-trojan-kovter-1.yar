rule Win_Trojan_Kovter_1
{
strings:
	$a0 = { 56578b44241450e817000000e870000000508d1c1203e86bde102bd95940e9d7ffffff }


condition:
	$a0
}