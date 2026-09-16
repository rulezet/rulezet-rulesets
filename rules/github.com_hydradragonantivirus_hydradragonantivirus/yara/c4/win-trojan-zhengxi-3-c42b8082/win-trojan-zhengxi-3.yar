rule Win_Trojan_Zhengxi_3
{
strings:
	$a0 = { 76b8ccf5fad3e285eecd1cf7c5e263760a81ebb26480d9c32a5a51b864a9263a1833ed81cdb7235581e75bbc0ed0 }


condition:
	$a0
}