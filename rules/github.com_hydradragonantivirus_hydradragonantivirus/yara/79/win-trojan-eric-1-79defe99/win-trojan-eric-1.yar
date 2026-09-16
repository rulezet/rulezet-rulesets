rule Win_Trojan_Eric_1
{
strings:
	$a0 = { 09ba6b01cd211e07b80107b90000b202cd13cd13cd13fec280fa1875e9beb3025052ac0ac0740b }


condition:
	$a0
}