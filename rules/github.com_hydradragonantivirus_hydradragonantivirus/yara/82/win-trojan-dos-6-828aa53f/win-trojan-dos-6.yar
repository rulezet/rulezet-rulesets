rule Win_Trojan_Dos_6
{
strings:
	$a0 = { 0400cd21803c4d74358b45108945213d00f8772a50 }


condition:
	$a0
}