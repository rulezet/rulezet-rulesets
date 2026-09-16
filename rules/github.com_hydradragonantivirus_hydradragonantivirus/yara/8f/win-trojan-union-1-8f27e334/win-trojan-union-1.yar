rule Win_Trojan_Union_1
{
strings:
	$a0 = { cd2132ed02cebe100103f1bfa906fc061e07b91000f3a407b9a905ba1001b440cd21e8bcffc3 }


condition:
	$a0
}