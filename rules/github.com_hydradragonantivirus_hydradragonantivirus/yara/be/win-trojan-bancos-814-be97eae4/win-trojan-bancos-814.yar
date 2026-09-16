rule Win_Trojan_Bancos_814
{
strings:
	$a0 = { 0f4999b29d63d97f7dcacafe05c7c087e8af88fa59b2fc46cb45f045861ecb33165f5fcb8cbe6dad83a82fd50ecb9161fb4fd12e7c4f8bb7fb931e91680f1cde6f8cfd9cade9 }


condition:
	$a0
}