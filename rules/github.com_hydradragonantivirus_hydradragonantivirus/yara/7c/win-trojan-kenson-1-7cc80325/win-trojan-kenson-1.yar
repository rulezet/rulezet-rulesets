rule Win_Trojan_Kenson_1
{
strings:
	$a0 = { 42e8eaffb440b90100ba1705e8c3feb440b90200ba3105e8b8feb440b90200ba1805e8adfec3 }


condition:
	$a0
}