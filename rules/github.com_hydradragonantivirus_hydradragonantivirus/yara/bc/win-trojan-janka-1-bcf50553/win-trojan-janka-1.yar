rule Win_Trojan_Janka_1
{
strings:
	$a0 = { 583d00a0730ab8ee61cd213daaee753c2e80be2b04457522071f66618cc00510002e0146502e03 }


condition:
	$a0
}