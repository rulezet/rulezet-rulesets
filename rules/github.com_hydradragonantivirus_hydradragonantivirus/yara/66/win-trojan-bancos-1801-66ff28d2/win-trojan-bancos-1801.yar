rule Win_Trojan_Bancos_1801
{
strings:
	$a0 = { dbd7baf8846d5aca43b01ac4d071d0b5f34467bb2e34856128f66cfcd787799b45c575c74c4e4f89fc1d4de2314d09c6f3e1b7fa6f6df58570aacc844e50a72060350e7daa98 }


condition:
	$a0
}