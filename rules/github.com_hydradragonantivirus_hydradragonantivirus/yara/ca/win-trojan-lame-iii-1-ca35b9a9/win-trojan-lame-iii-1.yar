rule Win_Trojan_Lame_III_1
{
strings:
	$a0 = { 1642cd21fa660fb7e4678b6c24fa81ed0500fb1e068cd8488ed82bffc6055a836d031890836d1218908b45128ed8c6 }


condition:
	$a0
}