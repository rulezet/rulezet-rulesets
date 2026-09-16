rule Win_Trojan_Stoned_7
{
strings:
	$a0 = { 80fa80751a4141b80103cdc3725b33db83e902c606040003b80103cdc3eb4a }


condition:
	$a0
}