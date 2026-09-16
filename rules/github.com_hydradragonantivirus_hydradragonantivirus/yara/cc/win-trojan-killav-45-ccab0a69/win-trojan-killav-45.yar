rule Win_Trojan_KillAV_45
{
strings:
	$a0 = { 33c0e994000000 }

	$a1 = { b0e1b013b077b09cb0886848e200108b45fc50ff1540e00010a32c040110b0e1b013b077b09cb088833d2c04011000750e }

	$a2 = { b0e1b013b077b09cb08833c0eb55 }

	$a3 = { 685ce20010ff1544e000108945fcb0e1b013b077b09cb088837dfc007504 }

	$a4 = { 33c0eb33 }

	$a5 = { 33c0 }

	$a6 = { 8be55dc3 }

	$a7 = { 558bec83ec54a1a00101108945f8b0e1b013b077b09cb088c645ff41eb08 }

	$a8 = { 0fbe4dff83f95a7f24 }

	$a9 = { b0e1b013b077b09cb088c645ff61eb09 }

	$a10 = { 0fbe55ff83fa7a7f24 }

	$a11 = { b0e1b013b077b09cb088c645ff30eb09 }

	$a12 = { 0fbe45ff83f8397f21 }

	$a13 = { 8b4dac83c101894dac }

	$a14 = { 8b55ac3b550c7374 }

	$a15 = { b0e1b013b077b09cb0880fbe45fd0fbe4dfe2bc18b55100fbe4402ff8b4dac034d0c0faf4d0c03c133d2b91a000000f7f18b45080345ac8a4c15ca8808b0e1b013b077b09cb0880fbe55fe0fbe45fd83e8013bd07d15 }

	$a16 = { b0e1b013b077b09cb0888a4dfe80c101884dfeeb04 }

	$a17 = { c645fe00 }

	$a18 = { b0e1b013b077b09cb0888b550803550cc602008b45088b4df8e87a0300008be55dc3 }

	$a19 = { 8b55e80fb6823b9f0010ff2485079f0010 }

	$a20 = { b0e1b013b077b09cb088c745ecffffffffb8010000008be55dc3 }

	$a21 = { 6a0c68b0e40010e875f6ffffc745e48cee0010 }

	$a22 = { 817de48cee00107322 }

	$a23 = { 8365fc008b45e48b0085c0740b }

	$a24 = { ffd0eb07 }

	$a25 = { 834dfcff8345e404ebd5 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25
}