rule Win_Trojan_CivilWar_16
{
strings:
	$a0 = { 3db002ba9e00cd218bd8b457b000cd215180e12f80f92c5974205152b440b9bc018d160001cd21 }


condition:
	$a0
}