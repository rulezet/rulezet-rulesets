rule Win_Trojan_SillyORC_8
{
strings:
	$a0 = { c0bf3c02be0001b90a00f3a6c3000000003d004b75101e529c2eff1e38025a1f9ce807009dcf2eff2e38025056 }


condition:
	$a0
}