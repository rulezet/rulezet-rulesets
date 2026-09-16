rule Win_Trojan_Schumann_1
{
strings:
	$a0 = { a9c48d81898ea4ecedd8e6a4a9c689aeae8ca9a2b6c2848fa4dadb }


condition:
	$a0
}