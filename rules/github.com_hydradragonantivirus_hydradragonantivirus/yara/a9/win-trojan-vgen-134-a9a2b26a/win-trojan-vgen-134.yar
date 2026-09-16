rule Win_Trojan_Vgen_134
{
strings:
	$a0 = { c0eb09b88fc6abf3a4b801002ea31500b430cd213d031e7509b434cd21bb6014eb05b82135cd }


condition:
	$a0
}