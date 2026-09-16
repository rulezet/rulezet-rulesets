rule Win_Trojan_DustySky_20
{
strings:
	$a0 = { 3f3f3f3f3f3f203f3f3f3f3f3f203f3f3f3f3f203f3f3f3f203f3f3f203f3f3f3f3f203f3f3f3f3f203f3f3f3f3f2e657865 }


condition:
	$a0
}