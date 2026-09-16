rule Win_Trojan_Trojan_210
{
strings:
	$a0 = { 5d83ed031e06b8e4e2cd2181fb20cd74678cc0488ed8832e03004090832e12004090a112008ed8408ec0c60600 }


condition:
	$a0
}