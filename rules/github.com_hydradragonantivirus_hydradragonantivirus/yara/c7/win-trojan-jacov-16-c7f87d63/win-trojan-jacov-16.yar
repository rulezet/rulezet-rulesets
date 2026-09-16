rule Win_Trojan_Jacov_16
{
strings:
	$a0 = { fabcfeff8cc88ed0fb1e0e070e1f8d86e103ffd02f69e9d4e9d7af812a7c8a5e29d7afba2a7c8a5629d6e17c8a }


condition:
	$a0
}