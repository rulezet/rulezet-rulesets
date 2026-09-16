rule Win_Trojan_GenVir_1
{
strings:
	$a0 = { a12001508b46142ea32001b4402e8b0e2201ba0001cd21582ea32001b80157 }


condition:
	$a0
}