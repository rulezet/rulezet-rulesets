rule Win_Trojan_Gogo_1
{
strings:
	$a0 = { 33c98ed1bcfc7bfc8ed9be657c410bc974fb8b0433c13dbefa75f2310cad81fef97d75f7 }


condition:
	$a0
}