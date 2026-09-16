rule Win_Trojan_USSR_34
{
strings:
	$a0 = { 5156b9ff00fc8bf28a04463c00e0f9 }


condition:
	$a0
}