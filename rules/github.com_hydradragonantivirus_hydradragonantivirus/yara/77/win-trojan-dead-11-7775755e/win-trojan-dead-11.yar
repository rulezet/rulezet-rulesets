rule Win_Trojan_Dead_11
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd211f1e071eb8000150cb3dadde740e }


condition:
	$a0
}