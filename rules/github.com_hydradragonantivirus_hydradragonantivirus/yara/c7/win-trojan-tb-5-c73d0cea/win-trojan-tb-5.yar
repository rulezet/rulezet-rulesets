rule Win_Trojan_TB_5
{
strings:
	$a0 = { be4001cd96cdec5ebe3c01cd96cdec5ebe3801cd96cdec5ebe3401cd96cdb8cdb2e90000eb }


condition:
	$a0
}