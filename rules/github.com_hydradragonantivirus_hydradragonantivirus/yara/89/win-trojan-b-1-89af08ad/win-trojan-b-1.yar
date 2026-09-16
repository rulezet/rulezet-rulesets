rule Win_Trojan_B_1
{
strings:
	$a0 = { 8ed8803e9200007412b451cd218edb803e0200c0750583060200405b581fcf }


condition:
	$a0
}