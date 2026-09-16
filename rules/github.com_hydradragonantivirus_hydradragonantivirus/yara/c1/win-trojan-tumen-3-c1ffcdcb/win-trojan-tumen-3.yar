rule Win_Trojan_Tumen_3
{
strings:
	$a0 = { ffcd213d00007406e82fffe8bfffe8 }


condition:
	$a0
}