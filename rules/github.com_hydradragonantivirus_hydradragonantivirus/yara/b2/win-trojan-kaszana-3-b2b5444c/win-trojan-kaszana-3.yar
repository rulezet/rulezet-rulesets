rule Win_Trojan_Kaszana_3
{
strings:
	$a0 = { 2e23d5ae39709f69728dca8c9b6ebda48a23f755800172dd5741ed47e0303aa064503eb46769b901 }


condition:
	$a0
}