rule Win_Trojan_Packed_32
{
strings:
	$a0 = { 159decffc68bcf0fcf8ae233d9f7d1eb019587f184f187da8bcf0fbbf7f3eb01c90fc0c3c1d615eb01e5f7d6fecc0fbafb41 }


condition:
	$a0
}