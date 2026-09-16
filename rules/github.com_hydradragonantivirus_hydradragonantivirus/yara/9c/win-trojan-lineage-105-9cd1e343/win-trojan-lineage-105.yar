rule Win_Trojan_Lineage_105
{
strings:
	$a0 = { e61cc292eec6a89d3afcbef52af265ee2c3ba7a2a39ca9b4be4ec08cf33a9555cee628749f9514f1ccce156393ea24b1d10958458fe5a3909f8173614df4cf70bab5cd1d }


condition:
	$a0
}