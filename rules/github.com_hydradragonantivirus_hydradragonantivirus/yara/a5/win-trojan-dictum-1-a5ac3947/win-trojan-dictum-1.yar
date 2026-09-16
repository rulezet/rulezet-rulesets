rule Win_Trojan_Dictum_1
{
strings:
	$a0 = { 5657525153508cc88ed88ec02e8b2e010181c5030106b42fcd212e899e77022e8c867902078bd581c2c202b41a }


condition:
	$a0
}