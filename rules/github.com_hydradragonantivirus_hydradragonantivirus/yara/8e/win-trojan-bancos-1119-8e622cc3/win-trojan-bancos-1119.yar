rule Win_Trojan_Bancos_1119
{
strings:
	$a0 = { 2e6f2ff44bb5ed7fee79d6e1e0db902fab35c49e186814e30128b1bb10007c3ce0476e4453e8cacc1be1a54cd3c293c1eaebc0614519c39f6e13f148c051f68b05b550af8e6990f1082a20c92d025b5eddfc }


condition:
	$a0
}