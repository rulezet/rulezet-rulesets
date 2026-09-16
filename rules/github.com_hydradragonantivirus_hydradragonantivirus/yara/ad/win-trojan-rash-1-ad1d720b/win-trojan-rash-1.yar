rule Win_Trojan_Rash_1
{
strings:
	$a0 = { 0e1f0e07be07008bfeb94c068a26b20680cc08fcac4932c4aa0bc975f7071f5f5ec39c2eff1ed606c3ac }


condition:
	$a0
}