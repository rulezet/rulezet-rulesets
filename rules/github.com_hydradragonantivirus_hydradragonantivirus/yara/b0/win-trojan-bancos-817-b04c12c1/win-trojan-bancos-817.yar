rule Win_Trojan_Bancos_817
{
strings:
	$a0 = { bb36e0283e33c12797f1df69bf0fae5067c67c67c67c67c7ed3c76abee3a3d7377f07f6c086fddf5ff5605de3a9fc37d197e5777df3c3747ff3605f9c5a27fb15b438ef82ab81dfcb3ffd0 }


condition:
	$a0
}