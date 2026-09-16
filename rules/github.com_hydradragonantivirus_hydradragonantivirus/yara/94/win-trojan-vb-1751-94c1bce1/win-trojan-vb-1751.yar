rule Win_Trojan_VB_1751
{
strings:
	$a0 = { 3837365c7900000000ffcc310015d4eaebc128426349bf74b3d017040757bc2e54773fbbfa4798 }


condition:
	$a0
}