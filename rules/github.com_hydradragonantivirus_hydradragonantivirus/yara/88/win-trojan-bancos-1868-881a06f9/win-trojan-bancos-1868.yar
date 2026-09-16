rule Win_Trojan_Bancos_1868
{
strings:
	$a0 = { ebdb0c981d229aaffd3c25d473e0185b2b234c906b89fe0eea76ca827bb7f7378b9527a96f1757e87b5a4dbcd1e8f820ff4fcfc8cb72defd4c78ea1e79597f998e9da8b96f15 }


condition:
	$a0
}