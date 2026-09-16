rule Win_Trojan_Apparition_1
{
strings:
	$a0 = { e800005e5683c61590e80200eb0ab9000180342046e2fac37e76a1e6d5209f2021dc84857e94deed }


condition:
	$a0
}