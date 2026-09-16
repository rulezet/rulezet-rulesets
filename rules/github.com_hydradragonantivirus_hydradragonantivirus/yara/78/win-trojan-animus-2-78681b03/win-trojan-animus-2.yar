rule Win_Trojan_Animus_2
{
strings:
	$a0 = { 3f1e57bfb23f1e57bff63f1e57bf00401e579ad501 }


condition:
	$a0
}