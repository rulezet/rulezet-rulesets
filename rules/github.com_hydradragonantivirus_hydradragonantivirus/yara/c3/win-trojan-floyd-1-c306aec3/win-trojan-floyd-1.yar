rule Win_Trojan_Floyd_1
{
strings:
	$a0 = { 052e8a0432c42e880446e2f5c36a400fa164a06c00a2be05e8dbffb44033d2b90606cd0172069090e8cbffc3e8c7ff5858e904fde900fa }


condition:
	$a0
}