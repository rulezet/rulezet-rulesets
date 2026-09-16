rule Win_Trojan_Chs_1
{
strings:
	$a0 = { ff009a0d009d005589e581ec00018dbe00ff165731c0509a7408ff00bf80211e57b84f00509a110bff00bfd821 }


condition:
	$a0
}