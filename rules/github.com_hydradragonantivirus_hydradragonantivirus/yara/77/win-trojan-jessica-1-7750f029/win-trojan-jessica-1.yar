rule Win_Trojan_Jessica_1
{
strings:
	$a0 = { 2e07019c3deeee7505b834129dcf50535152061e5756 }


condition:
	$a0
}