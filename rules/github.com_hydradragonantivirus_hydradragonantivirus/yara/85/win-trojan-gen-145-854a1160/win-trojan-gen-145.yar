rule Win_Trojan_Gen_145
{
strings:
	$a0 = { 3e2241007415ff7606ff362241b8020050e82a2e83c4060bc0740db8123e50b8693c50e8551d59 }


condition:
	$a0
}