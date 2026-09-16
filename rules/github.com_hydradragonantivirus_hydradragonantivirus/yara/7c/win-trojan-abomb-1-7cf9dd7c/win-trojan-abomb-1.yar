rule Win_Trojan_Abomb_1
{
strings:
	$a0 = { ee03bf000157b499cd2180fc66751481c6d502b90500f3a433f633ff33c933db33c0c3b452cd21268b5ffe8ec326 }


condition:
	$a0
}