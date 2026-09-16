rule Win_Trojan_TB_7
{
strings:
	$a0 = { cd95cd35062001cd3b1e2c00cd3da12c00cdadcd95cdec5ecd81e82101cdee04cd35062801cd }


condition:
	$a0
}