rule Win_Trojan_Lewd_2
{
strings:
	$a0 = { a3b90c26a186002ea3bb0c07589c2eff1eb90ceb059003011998b457b0018b1e06018b0e40018b }


condition:
	$a0
}