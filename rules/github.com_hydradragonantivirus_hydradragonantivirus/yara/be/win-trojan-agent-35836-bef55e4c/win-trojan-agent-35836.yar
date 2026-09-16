rule Win_Trojan_Agent_35836
{
strings:
	$a0 = { 686c2e657865[0-2]41657175697461733d53637265656e }

	$a1 = { 4165717569746173426c6f636b6572 }


condition:
	$a0 and $a1
}