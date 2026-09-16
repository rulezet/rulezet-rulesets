rule Win_Trojan_Mini_52
{
strings:
	$a0 = { 2701cd21721db8023dba9e00cd21720fba000193b440b92d00cd21b43ecd21b44febdf }


condition:
	$a0
}