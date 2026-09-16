rule Win_Trojan_Omega_4
{
strings:
	$a0 = { 1fe800005d8daeaf01b41a8bd5cd218d7e30897e2ee8c200e867008d7e308d76fb90e83600897e2ee8af00e85400b42acd213c05750a80fa0d7505e82500 }


condition:
	$a0
}