rule Win_Trojan_Dyfuca_7
{
strings:
	$a0 = { 812c4100880d802c4100c605822c410000eb25bfc8d2400083c9ff33c0f2aef7d12bf98bd18bf7bf802c4100c1e902f3a58bca83e103f3a483c9ffbfb8d240 }


condition:
	$a0
}