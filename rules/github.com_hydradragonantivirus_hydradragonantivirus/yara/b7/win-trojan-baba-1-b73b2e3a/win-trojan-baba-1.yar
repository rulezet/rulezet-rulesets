rule Win_Trojan_Baba_1
{
strings:
	$a0 = { 5ee800005e1e06568cc88ec08ed8bf000181c6????b90400fcf3a45eb8ababcd213daffa75 }


condition:
	$a0
}