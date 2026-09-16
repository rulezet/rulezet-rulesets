rule Win_Trojan_Small_4242
{
strings:
	$a0 = { 29c98d99dc3df9fc8d9b243647 }


condition:
	$a0
}