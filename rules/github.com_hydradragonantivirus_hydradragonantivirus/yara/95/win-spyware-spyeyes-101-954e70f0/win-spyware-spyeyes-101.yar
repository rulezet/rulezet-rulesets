rule Win_Spyware_SpyEyes_101
{
strings:
	$a0 = { ff3003daf7d203c7c3 }


condition:
	$a0
}