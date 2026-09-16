rule Win_Trojan_WilliWonka_1
{
strings:
	$a0 = { 1e0633db8ec3bb1a0053268f0608000e268f060a00cd02cd2083c40633db26813e0e0200f27503e987008cd8488ec0 }


condition:
	$a0
}