rule Win_Trojan_Goma_6
{
strings:
	$a0 = { 02e8580081fac5f9774e83fa0e724981ea3a053b963e06743f81c23a0589960b048d963d06cd21 }


condition:
	$a0
}