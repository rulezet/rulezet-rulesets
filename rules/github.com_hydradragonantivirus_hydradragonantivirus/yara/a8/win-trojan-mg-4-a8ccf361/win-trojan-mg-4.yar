rule Win_Trojan_MG_4
{
strings:
	$a0 = { 03b440b9f401ba0102cdff7213b800 }


condition:
	$a0
}