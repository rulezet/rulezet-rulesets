rule Win_Trojan_Waledac_45
{
strings:
	$a0 = { c0c51af6d7c0ef0ed2cad2d0d2cc81ff086d287e0f85310e0000769ef8ca }


condition:
	$a0
}