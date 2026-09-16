rule Win_Trojan_VGEN_192
{
strings:
	$a0 = { 04008d9e1f03ffd37a58f7b1e3f04421c1f45c2fc1f47c2ec18635a035a039c4e6594fea727e0f5ddc7b4fca897d7d }


condition:
	$a0
}