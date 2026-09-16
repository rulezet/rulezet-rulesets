rule Win_Trojan_VGEN_593
{
strings:
	$a0 = { 09ba5b01cd211e07b80107b90000b202cd13cd13cd13fec280fa1875e9be9b025052ac0ac0740b86d080ea5db402cd }


condition:
	$a0
}