rule Win_Trojan_TB_6
{
strings:
	$a0 = { cdb8cdb2cdec4c50010000cdec9abe2001cd9abe4c01cd96cdb8be2001cd96cdb8be4801cd96 }


condition:
	$a0
}