rule Win_Trojan_VGEN_255
{
strings:
	$a0 = { ac08c07442ac3c0d743d3c2074f789f74fac3c0d74043c2075f7c644ff00ba4e01b40acd2189fab43c29c9e9cf }


condition:
	$a0
}