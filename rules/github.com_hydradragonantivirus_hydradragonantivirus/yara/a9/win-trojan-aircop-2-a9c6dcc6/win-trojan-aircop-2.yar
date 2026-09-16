rule Win_Trojan_Aircop_2
{
strings:
	$a0 = { a3b87db83101a3bc7dff0e1304cd12 }


condition:
	$a0
}