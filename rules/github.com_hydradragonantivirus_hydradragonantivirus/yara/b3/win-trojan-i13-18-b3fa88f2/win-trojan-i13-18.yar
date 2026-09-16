rule Win_Trojan_I13_18
{
strings:
	$a0 = { 0300b813cdcd213d21cd745006b82135cd212e899ec0012e8c86c2018cd8488ec026a103002d3800931e07b44a }


condition:
	$a0
}