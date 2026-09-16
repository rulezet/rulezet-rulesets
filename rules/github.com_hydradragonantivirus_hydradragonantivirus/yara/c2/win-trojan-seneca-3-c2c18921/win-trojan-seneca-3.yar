rule Win_Trojan_Seneca_3
{
strings:
	$a0 = { eb2b90bb3301b9bd01908a2780f4ff882743 }


condition:
	$a0
}