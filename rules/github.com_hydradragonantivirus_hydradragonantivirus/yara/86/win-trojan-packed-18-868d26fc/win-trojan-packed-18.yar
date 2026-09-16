rule Win_Trojan_Packed_18
{
strings:
	$a0 = { 60be8d314100bf001040 }

	$a1 = { fffffffffffffffff7070000008ff000000ffffffffffffff7070000008ffffffffffffffffffffff7070000008ffffffffffffffffffffff7070000008ff000 }


condition:
	$a0 and $a1
}