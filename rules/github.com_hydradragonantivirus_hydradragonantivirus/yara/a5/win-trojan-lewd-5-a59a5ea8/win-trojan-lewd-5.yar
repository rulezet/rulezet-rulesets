rule Win_Trojan_Lewd_5
{
strings:
	$a0 = { 061e0e1f8cc005100003062801a3d403a12a01a3d203b8baabcd213d4d497458 }


condition:
	$a0
}