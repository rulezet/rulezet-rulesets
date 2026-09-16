rule Win_Trojan_SillyC_142
{
strings:
	$a0 = { 5351521e0656e800005efc0e1f0e07bf00015681c6f400b90300f3a45eb41a89f281c2c300cd21b44e89f281c2ee }


condition:
	$a0
}