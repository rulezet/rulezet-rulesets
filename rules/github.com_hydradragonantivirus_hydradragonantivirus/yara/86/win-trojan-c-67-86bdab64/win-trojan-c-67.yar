rule Win_Trojan_C_67
{
strings:
	$a0 = { 89160d03b430cd218b2e02008b1e2c008edaa377568c067556891e7156892e8d56e81601c43e6f568bc78bd8b9 }


condition:
	$a0
}