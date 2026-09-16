rule Win_Trojan_Tiny_36
{
strings:
	$a0 = { 8bfe4ebb3206b95000037402a5a48ec1a674144ebf5905f3a58ec1939191268785e0feabe3f7931e0761ffe63d004b }


condition:
	$a0
}