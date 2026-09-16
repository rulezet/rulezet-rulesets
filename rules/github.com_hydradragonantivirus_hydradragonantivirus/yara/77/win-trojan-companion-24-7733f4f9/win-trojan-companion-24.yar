rule Win_Trojan_Companion_24
{
strings:
	$a0 = { cd21bf5301891d8c4502ba1801b425cd2189facd273d004b753550061e0789d7b02ef2ae57b84558abaa5f0758 }


condition:
	$a0
}