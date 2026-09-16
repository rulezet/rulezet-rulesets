rule Win_Trojan_Silly_40
{
strings:
	$a0 = { 565fe800005e81c6590056b103f3a48bd65e4880c44fcd2172378bfeb43ee83100b43fe82500803de974e8b8024233 }


condition:
	$a0
}