rule Win_Trojan_Sirius_17
{
strings:
	$a0 = { 5f4d85ed75cafcc0077f9ea4ceb011410bcbf2ba9bd076f86e83fcf9e713b7177d99dcbf4a34 }


condition:
	$a0
}