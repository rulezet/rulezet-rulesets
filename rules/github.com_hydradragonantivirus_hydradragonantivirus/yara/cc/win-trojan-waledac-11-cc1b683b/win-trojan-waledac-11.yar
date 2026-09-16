rule Win_Trojan_Waledac_11
{
strings:
	$a0 = { 0305c09d4e0083f8190f8409000000090dc08f }


condition:
	$a0
}