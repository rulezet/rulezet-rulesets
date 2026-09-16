rule Win_Trojan_DSPDH_1
{
strings:
	$a0 = { 9801b90000ba0000cd21b4408b1e9801b90500baf402cd21803efa02017509a1a301050301a3 }


condition:
	$a0
}