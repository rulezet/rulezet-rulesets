rule Win_Trojan_SillyOR_11
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21ba5101cd2780fc3d7405ea00 }


condition:
	$a0
}