rule Win_Trojan_Wtfm_6
{
strings:
	$a0 = { 80c44ee80a002a3f3f3f3f2e436f4d005ab954d381c1cc2ce80a007317e8ac0045248d2f75cd21c35f2ae480cc9a3225 }


condition:
	$a0
}