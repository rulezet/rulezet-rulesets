rule Win_Trojan_MAD_7
{
strings:
	$a0 = { e90600f616e816da165287f6760087ff87db8bc98bc98bd2740081fe0d0dc3 }


condition:
	$a0
}