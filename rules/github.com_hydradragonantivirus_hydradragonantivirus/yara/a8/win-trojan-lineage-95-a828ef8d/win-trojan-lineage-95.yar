rule Win_Trojan_Lineage_95
{
strings:
	$a0 = { d64b70b8932b8f3acc126c21bc67f7363563bfba9cb84f37e6aa7a9d5328e81ed30b52550d5e65d7772f97e8120cb2e73987548324e0f83ae96bd5a85e9f944d46c28a80 }


condition:
	$a0
}