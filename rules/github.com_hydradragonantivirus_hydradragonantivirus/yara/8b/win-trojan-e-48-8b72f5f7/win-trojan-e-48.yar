rule Win_Trojan_E_48
{
strings:
	$a0 = { 756e640d0a42656c65676e756d6d6572205b }

	$a1 = { 6c7320544d53204c6f67697374696b204b75 }


condition:
	$a0 and $a1
}