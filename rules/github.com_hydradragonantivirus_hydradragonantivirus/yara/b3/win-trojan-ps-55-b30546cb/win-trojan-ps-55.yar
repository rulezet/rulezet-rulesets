rule Win_Trojan_PS_55
{
strings:
	$a0 = { b8023dcc93b80057cc51528d96????b91a00b43fcc33c9b8024299cc81be????4d5a740c }


condition:
	$a0
}