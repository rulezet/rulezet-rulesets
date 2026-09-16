rule Win_Trojan_Packed_101
{
strings:
	$a0 = { 98dc6a3a8ed86a3a9abaebb798f86a3a3fc26c990d20d8a90d30d83a13c0de4a13d0de5a13e0de6a9aba64bb13f0de7a }


condition:
	$a0
}