rule Crypton_kp__32_lil_16_
{
strings:
	$a0 = { 85ae67bb72f36e3c3af54fa57f520e51 }

condition:
	$a0
}