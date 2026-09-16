rule Win_Trojan_Ache_1
{
strings:
	$a0 = { caeb0a908b165a014289165a01890e5801e85effb440ba5601b9180090cd215a59b80157cd21c3 }


condition:
	$a0
}