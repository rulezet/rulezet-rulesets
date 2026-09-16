rule Win_Trojan_Vienna_13
{
strings:
	$a0 = { bc005681c6d201bf0001b90300f3a45eb44ebac90101f2b9ffffcd21723d52b8023dba9e00cd21722b8bd88b0e9c008b169a0083ea02b80142cd21bad50101 }


condition:
	$a0
}