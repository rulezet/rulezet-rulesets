rule Win_Trojan_V_85
{
strings:
	$a0 = { b80042cd2172ccb440ba8403b91800cd2172c031c98bd1b80242cd2172b58b16de038cd848 }


condition:
	$a0
}