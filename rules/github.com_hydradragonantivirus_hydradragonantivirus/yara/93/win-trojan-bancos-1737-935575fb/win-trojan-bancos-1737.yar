rule Win_Trojan_Bancos_1737
{
strings:
	$a0 = { ac22a9a87dc930ff110a17ea06a113a16f8cc59ebe7b79cfd8a224520a0127980baaa5df35c1ee15b2086a89687f81eb41baf468cb2cf3b6d21d79d0ff5a8e6e9ccef10d3f09 }


condition:
	$a0
}