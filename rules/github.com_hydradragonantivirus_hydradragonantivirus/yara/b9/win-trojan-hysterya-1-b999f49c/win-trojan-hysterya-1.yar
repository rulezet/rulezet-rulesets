rule Win_Trojan_Hysterya_1
{
strings:
	$a0 = { 0e1f06e800005d81ed0801b8dabecd213dccfaf87506909090e9aa00b82135cd21899ebf048c86c104b81035cd21 }


condition:
	$a0
}