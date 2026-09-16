rule Win_Trojan_DustySky_22
{
strings:
	$a0 = { 4175746f44656331396669782e657865 }


condition:
	$a0
}