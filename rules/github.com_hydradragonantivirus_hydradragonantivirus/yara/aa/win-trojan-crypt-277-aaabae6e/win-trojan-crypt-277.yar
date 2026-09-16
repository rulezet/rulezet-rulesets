rule Win_Trojan_Crypt_277
{
strings:
	$a0 = { 53797352756e00006f6b6e6173686f70732e636f6d }

	$a1 = { 47455420257325732048545450 }

	$a2 = { 6572735c4669726577616c6c506f }


condition:
	$a0 and $a1 and $a2
}