rule Win_Dropper_Agent_34404
{
strings:
	$a0 = { 89c68d4dd8ba4c2b4000b8742b4000e8c3feffff8b45d8e81beeffff5053ffd68945f48d4dd4ba4c2b4000b88c2b4000e8a2feffff8b45d4e8faedffff }


condition:
	$a0
}