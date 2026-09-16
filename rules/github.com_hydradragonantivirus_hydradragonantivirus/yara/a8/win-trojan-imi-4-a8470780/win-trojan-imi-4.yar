rule Win_Trojan_IMI_4
{
strings:
	$a0 = { 6a00250f00ba10002bd083e20fb8024233c99cff1e700072e6b440b9780633d29cff1e7000 }


condition:
	$a0
}