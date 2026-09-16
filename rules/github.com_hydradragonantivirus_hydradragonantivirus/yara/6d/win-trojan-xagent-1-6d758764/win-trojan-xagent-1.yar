rule Win_Trojan_Xagent_1
{
strings:
	$a0 = { 5375626a6563743a20706972616469206e6f6d6572690d0a }


condition:
	$a0
}