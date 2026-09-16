rule Win_Trojan_Dikshev_6
{
strings:
	$a0 = { 8bd581ea3e3281c2323233c9b1decd21b8fd41e859ff998bcacd218bc48bf8e84dff96ad9681 }


condition:
	$a0
}