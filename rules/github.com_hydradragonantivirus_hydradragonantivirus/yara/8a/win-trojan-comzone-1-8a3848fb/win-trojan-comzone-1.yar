rule Win_Trojan_Comzone_1
{
strings:
	$a0 = { 3d00047236803e2602e9750c8bc881e90002390e27027423a3fe02b440b90002ba0001cd21721433 }


condition:
	$a0
}