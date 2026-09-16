rule Win_Trojan_Gen_165
{
strings:
	$a0 = { 36cc0aff36d00aff36d20a9a2200e400bfca071e57bfda0a1e57b8000850bfd60a1e579a }


condition:
	$a0
}