rule Win_Trojan_Bancos_1030
{
strings:
	$a0 = { 6985fd10ce3fd0292c28ba24f5d196e157a507db2f5311481acf3889a581ba97aed533b4017eee60fb7fad4730c0e9cf5af5a9e697c75a258e6796d2679b0e3b }


condition:
	$a0
}