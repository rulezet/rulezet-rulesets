rule Win_Trojan_Bancos_691
{
strings:
	$a0 = { 1b66bdd4f16027da42c6ba40490876fc8b1bcdd0abaaed7c4061759e08813a4b08e74507ed2a702ccc73b56941538edd90440594c0526d0c7bd05e6271072a47 }


condition:
	$a0
}