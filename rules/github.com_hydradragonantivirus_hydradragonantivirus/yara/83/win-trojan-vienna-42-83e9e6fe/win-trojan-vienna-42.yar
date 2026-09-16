rule Win_Trojan_Vienna_42
{
strings:
	$a0 = { 88028bd681eaf901cd21721f3d88 }


condition:
	$a0
}