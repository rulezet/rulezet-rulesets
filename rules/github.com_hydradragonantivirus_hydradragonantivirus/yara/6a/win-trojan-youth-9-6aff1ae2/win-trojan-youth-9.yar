rule Win_Trojan_Youth_9
{
strings:
	$a0 = { db04b9db03e8d3fe72b83bc175b4b8004233c933d2e8c3feb440b9db03ba0001e8b8fe8026 }


condition:
	$a0
}