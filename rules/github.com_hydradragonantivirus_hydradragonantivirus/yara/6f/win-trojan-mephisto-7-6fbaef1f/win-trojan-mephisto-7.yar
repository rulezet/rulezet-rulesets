rule Win_Trojan_Mephisto_7
{
strings:
	$a0 = { be1801b90c022e8bb631052e31354747e2f9c3 }


condition:
	$a0
}