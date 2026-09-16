rule Win_Trojan_Bancos_1009
{
strings:
	$a0 = { f27935bceccbce1ccbca5c98651fedbbab4b3a7fa8264f9ce505ac011639bec6ed847b8f0b0fae209f3b940c64b9aed28e38e6a508bc6f448ee8dea63cf05e814226e5b2e6d6eec8ab01a3eea19f7bccf6a5 }


condition:
	$a0
}