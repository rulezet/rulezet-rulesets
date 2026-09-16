rule Win_Trojan_Abraxas_8
{
strings:
	$a0 = { 44fde98944feb4408d960301b9db07cd21b8004233c999cd21b4408d964b0959cd21fe8e4a09 }


condition:
	$a0
}