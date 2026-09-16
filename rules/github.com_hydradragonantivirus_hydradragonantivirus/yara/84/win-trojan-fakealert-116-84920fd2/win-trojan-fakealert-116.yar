rule Win_Trojan_Fakealert_116
{
strings:
	$a0 = { e81b0000009d3f13000ba4efe2e000bce767c400a30000359700000000000000648b3530 }


condition:
	$a0
}