rule Win_Trojan_Trivial_416
{
strings:
	$a0 = { 39baec02cd21b43cba0000b99001424ae2fc8bcabaf202 }


condition:
	$a0
}