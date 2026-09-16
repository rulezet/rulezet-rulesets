rule Win_Trojan_Terror_3
{
strings:
	$a0 = { 59eccd213be8753e0e1f582e8e06 }


condition:
	$a0
}