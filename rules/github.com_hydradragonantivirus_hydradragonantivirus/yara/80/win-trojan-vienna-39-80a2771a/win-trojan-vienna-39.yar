rule Win_Trojan_Vienna_39
{
strings:
	$a0 = { b96a028bd681eadb01cd21721f3d }


condition:
	$a0
}